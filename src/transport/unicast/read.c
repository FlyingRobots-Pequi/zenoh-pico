//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

#include "zenoh-pico/transport/unicast/read.h"

#include <stddef.h>
#include <stdint.h>

#include "zenoh-pico/api/types.h"
#include "zenoh-pico/config.h"
#include "zenoh-pico/protocol/codec/transport.h"
#include "zenoh-pico/session/interest.h"
#include "zenoh-pico/system/common/platform.h"
#include "zenoh-pico/transport/common/rx.h"
#include "zenoh-pico/transport/transport.h"
#include "zenoh-pico/transport/unicast/rx.h"
#include "zenoh-pico/utils/logging.h"

// ===================== INSTRUMENTACAO TEMPORARIA (2026-09-24) =====================
// Contadores para localizar ONDE a read task para de drenar o socket TCP
// (local_position_diagnostico_2026-09-23.md, secao 6). Lidos por `zenoh status`
// -> ZENOH::print_status() em src/modules/zenoh/zenoh.cpp, que roda na thread do
// shell e continua respondendo com a read task travada.
//
// Sao "in"/"out" em pares de propósito: o par cujo delta (in - out) fica preso em
// 1 e a moldura onde a thread parou. Ler DUAS vezes com ~1 s de intervalo: o que
// distingue travado de apenas lento e o contador nao andar entre as amostras.
//
// REMOVER quando o bug estiver fechado.
volatile uint32_t g_zp_loop;         // iteracoes do while do read task
volatile uint32_t g_zp_recv_in;      // chamadas a _z_unicast_client_read
volatile uint32_t g_zp_recv_out;     // retornos dela (in>out = preso no recv)
volatile uint32_t g_zp_recv_data;    // retornos COM dados (true)
volatile uint32_t g_zp_proc_in;      // entradas em _z_unicast_process_messages
volatile uint32_t g_zp_proc_out;     // saidas dela
volatile uint32_t g_zp_handle_in;    // entradas em _z_unicast_handle_transport_message
volatile uint32_t g_zp_handle_out;   // saidas dela (in>out = preso no dispatch,
                                     // que e por onde o callback do subscriber roda)
// Diagnostico do batch: se o router mandar um batch maior que a capacidade do
// _zbuf (que vale o _batch_size NEGOCIADO, ver unicast/transport.c:58), entao
// _z_zbuf_len < to_read e insatisfazivel e o laco abaixo rebobina/compacta/
// devolve false PARA SEMPRE, sem nunca consumir os bytes. g_zp_toread_max >
// g_zp_zbuf_cap prova esse caso.
volatile uint32_t g_zp_short_read;   // vezes que bailou por faltar byte
volatile uint32_t g_zp_toread_last;  // ultimo to_read pedido
volatile uint32_t g_zp_toread_max;   // maior to_read ja visto
volatile uint32_t g_zp_zbuf_cap;     // capacidade do _zbuf
volatile uint32_t g_zp_zbuf_len;     // preenchimento no momento do bail
// O que o recv() efetivamente devolve. _z_link_socket_recv_zbuf devolve
// SIZE_MAX em EAGAIN (timeout do SO_RCVTIMEO, link vivo e sem dado) e 0 em EOF
// (peer fechou). Distinguir os dois e o que separa "o kernel nao tem dado" de
// "o socket morreu" -- indistinguiveis pelos contadores anteriores.
volatile uint32_t g_zp_rv_bytes;     // chamadas que devolveram N>0
volatile uint32_t g_zp_rv_zero;      // devolveram 0   (EOF)
volatile uint32_t g_zp_rv_eagain;    // devolveram SIZE_MAX (timeout/EAGAIN)
volatile uint32_t g_zp_rv_last;      // ultimo N devolvido (SIZE_MAX vira 0xFFFFFFFF)
volatile uint32_t g_zp_rv_total;     // soma de bytes recebidos
// ==================================================================================

#define _Z_UNICAST_PEER_READ_STATUS_OK 0
#define _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA -1
#define _Z_UNICAST_PEER_READ_STATUS_SOCKET_CLOSED -2
#define _Z_UNICAST_PEER_READ_STATUS_CRITICAL_ERROR -3

#if Z_FEATURE_UNICAST_TRANSPORT == 1

static z_result_t _z_unicast_process_messages(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer,
                                              size_t to_read) {
    // Wrap the main buffer to_read bytes
    _z_zbuf_t zbuf;
    if (peer->flow_state == _Z_FLOW_STATE_READY) {
        zbuf = _z_zbuf_view(&peer->flow_buff, to_read);
    } else {
        zbuf = _z_zbuf_view(&ztu->_common._zbuf, to_read);
    }

    peer->common._received = true;
    while (_z_zbuf_len(&zbuf) > 0) {
        // Decode one session message
        _z_transport_message_t t_msg;
        z_result_t ret = _z_transport_message_decode(&t_msg, &zbuf);

        if (ret != _Z_RES_OK) {
            _Z_INFO("Connection compromised due to malformed message: %d", ret);
            return ret;
        }
        g_zp_handle_in++;  // INSTRUMENTACAO
        ret = _z_unicast_handle_transport_message(ztu, &t_msg, peer);
        g_zp_handle_out++;  // INSTRUMENTACAO
        if (ret != _Z_RES_OK) {
            if (ret != _Z_ERR_CONNECTION_CLOSED) {
                _Z_WARN("Connection compromised due to message processing error: %d", ret);
            }
            return ret;
        }
    }
    // Move the read position of the read buffer
    if (peer->flow_state == _Z_FLOW_STATE_READY) {
        _z_zbuf_set_rpos(&peer->flow_buff, _z_zbuf_get_rpos(&peer->flow_buff) + to_read);
    } else {
        _z_zbuf_set_rpos(&ztu->_common._zbuf, _z_zbuf_get_rpos(&ztu->_common._zbuf) + to_read);
    }

    if (_z_unicast_update_rx_buffer(ztu) != _Z_RES_OK) {
        _Z_ERROR("Connection closed due to lack of memory to allocate rx buffer");
        _Z_ERROR_RETURN(_Z_ERR_SYSTEM_OUT_OF_MEMORY);
    }
    return _Z_RES_OK;
}

// INSTRUMENTACAO: contabiliza um retorno de _z_link_socket_recv_zbuf
static inline void _zp_count_recv(size_t rb) {
    if (rb == SIZE_MAX) {
        g_zp_rv_eagain++;
        g_zp_rv_last = 0xFFFFFFFFu;
    } else if (rb == 0) {
        g_zp_rv_zero++;
        g_zp_rv_last = 0;
    } else {
        g_zp_rv_bytes++;
        g_zp_rv_last = (uint32_t)rb;
        g_zp_rv_total += (uint32_t)rb;
    }
}

static bool _z_unicast_client_read(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer, size_t *to_read) {
    switch (ztu->_common._link->_cap._flow) {
        case Z_LINK_CAP_FLOW_STREAM:
            // rb == 0 means the socket returned a clean EOF (peer closed the TCP connection):
            // recv() does NOT block for that, it returns immediately, every single call. A live
            // connection with merely no data pending returns SIZE_MAX instead (EAGAIN, after
            // blocking up to SO_RCVTIMEO) -- that case does not busy-loop and is left alone.
            //
            // In CLIENT mode (our case: net.txt says `client;tcp/...`) nothing else here checks
            // for EOF, so without this sleep the caller's while(!should_exit()) loop spins this
            // thread at ~100% CPU with no delay, for as long as it takes the lease task to notice
            // (Z_TRANSPORT_LEASE, 60s) -- and worse, while spinning it keeps _mutex_rx held and
            // keeps touching _link/_zbuf, which is exactly the state _zp_unicast_failed() then
            // tears down. See the join-not-detach fix in transport/common/transport.c for why
            // that specific race can corrupt memory; this sleep only bounds how long the CPU
            // burns and how often the race window is hit -- it doesn't fix the race by itself.
            //
            // The two `if` guards below are unchanged from upstream on purpose: they skip the
            // recv() call once enough bytes are already buffered from a prior partial read, and
            // duplicating that recv() here would silently double the worst-case per-iteration
            // block time (up to 2x SO_RCVTIMEO instead of 1x) on a healthy but momentarily idle
            // connection. What is new here is the EOF check and the compaction right below.
            //
            // Compact FIRST, on every call. Upstream only compacts when bailing out, so after a
            // batch is processed the leftover bytes stay at the END of the buffer (r_pos == the
            // size of the batch just consumed). The next recv() then only has `cap - w_pos` bytes
            // of room -- and when a previous recv() filled the buffer to the brim, that room is
            // ZERO: recv(len = 0) returns 0 immediately, which is indistinguishable from EOF and
            // hit the 50 ms sleep above ONCE PER MESSAGE. Measured on the bench (2026-09-26): the
            // FCU drained ~18 msg/s, the router went rwnd-limited 78% of the time at 30 Hz of
            // visual odometry, and the backlog is what made the TCP receive race in NuttX
            // (net/tcp/tcp_recvfrom.c) fire. With the leftover moved to the start, the room is
            // always >= batch_size - len (the zbuf holds batch_size + 2, see transport.c), so a
            // recv() is never issued with zero room and rb == 0 means a real EOF again.
            _z_zbuf_compact(&ztu->_common._zbuf);
            if (_z_zbuf_len(&ztu->_common._zbuf) < _Z_MSG_LEN_ENC_SIZE) {
                size_t rb = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
                _zp_count_recv(rb);  // INSTRUMENTACAO
                if (rb == 0) {
                    z_sleep_ms(50);
                }
                if (_z_zbuf_len(&ztu->_common._zbuf) < _Z_MSG_LEN_ENC_SIZE) {
                    _z_zbuf_compact(&ztu->_common._zbuf);
                    return false;
                }
            }
            // Get stream size
            *to_read = _z_read_stream_size(&ztu->_common._zbuf);
            // Read data
            if (_z_zbuf_len(&ztu->_common._zbuf) < *to_read) {
                size_t rb = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
                _zp_count_recv(rb);  // INSTRUMENTACAO
                if (rb == 0) {
                    z_sleep_ms(50);
                }
                if (_z_zbuf_len(&ztu->_common._zbuf) < *to_read) {
                    // INSTRUMENTACAO
                    g_zp_short_read++;
                    g_zp_toread_last = (uint32_t)*to_read;
                    if ((uint32_t)*to_read > g_zp_toread_max) { g_zp_toread_max = (uint32_t)*to_read; }
                    g_zp_zbuf_cap = (uint32_t)_z_zbuf_capacity(&ztu->_common._zbuf);
                    g_zp_zbuf_len = (uint32_t)_z_zbuf_len(&ztu->_common._zbuf);
                    _z_zbuf_set_rpos(&ztu->_common._zbuf, _z_zbuf_get_rpos(&ztu->_common._zbuf) - _Z_MSG_LEN_ENC_SIZE);
                    _z_zbuf_compact(&ztu->_common._zbuf);
                    return false;
                }
            }
            break;
        case Z_LINK_CAP_FLOW_DATAGRAM:
            _z_zbuf_compact(&ztu->_common._zbuf);
            *to_read = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
            if (*to_read == SIZE_MAX) {
                return false;
            }
            break;
        default:
            break;
    }
    return true;
}

z_result_t _zp_unicast_read(_z_transport_unicast_t *ztu, bool single_read) {
    _z_transport_peer_unicast_t *curr_peer = _z_transport_peer_unicast_slist_value(ztu->_peers);
    if (curr_peer == NULL) {
        _Z_ERROR("Invalid router endpoint\n");
        _Z_ERROR_RETURN(_Z_ERR_TRANSPORT_RX_FAILED);
    }
    // Read & process a single message
    if (single_read) {
        _z_transport_message_t t_msg;
        _Z_RETURN_IF_ERR(_z_unicast_recv_t_msg(ztu, &t_msg));
        _Z_CLEAN_RETURN_IF_ERR(_z_unicast_handle_transport_message(ztu, &t_msg, curr_peer), _z_t_msg_clear(&t_msg));
        _z_t_msg_clear(&t_msg);
        // Update buffer
        _Z_RETURN_IF_ERR(_z_unicast_update_rx_buffer(ztu));
    } else {
        // Prepare buffer
        _z_zbuf_reset(&ztu->_common._zbuf);
        size_t to_read = 0;
        // Retrieve data if any
        if (_z_unicast_client_read(ztu, curr_peer, &to_read)) {
            // Process data
            _Z_RETURN_IF_ERR(_z_unicast_process_messages(ztu, curr_peer, to_read))
        } else {
            return _Z_NO_DATA_PROCESSED;
        }
    }
    return _Z_RES_OK;
}
#else

z_result_t _zp_unicast_read(_z_transport_unicast_t *ztu, bool single_read) {
    _ZP_UNUSED(ztu);
    _ZP_UNUSED(single_read);
    _Z_ERROR_RETURN(_Z_ERR_TRANSPORT_NOT_AVAILABLE);
}
#endif  // Z_FEATURE_UNICAST_TRANSPORT == 1

#if Z_FEATURE_MULTI_THREAD == 1 && Z_FEATURE_UNICAST_TRANSPORT == 1

static z_result_t _z_unicast_handle_remaining_data(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer,
                                                   size_t extra_size, size_t *to_read, bool *message_to_process) {
    *message_to_process = false;
    if (extra_size < _Z_MSG_LEN_ENC_SIZE) {
        peer->flow_state = _Z_FLOW_STATE_PENDING_SIZE;
        peer->flow_curr_size = _z_zbuf_read(&ztu->_common._zbuf);
        return _Z_RES_OK;
    }
    // Get stream size
    *to_read = _z_read_stream_size(&ztu->_common._zbuf);
    if (_z_zbuf_len(&ztu->_common._zbuf) < *to_read) {
        peer->flow_state = _Z_FLOW_STATE_PENDING_DATA;
        peer->flow_curr_size = (uint16_t)*to_read;
        peer->flow_buff = _z_zbuf_make(peer->flow_curr_size);
        if (_z_zbuf_capacity(&peer->flow_buff) != peer->flow_curr_size) {
            _Z_ERROR("Not enough memory to allocate flow state buffer");
            _Z_ERROR_RETURN(_Z_ERR_SYSTEM_OUT_OF_MEMORY);
        }
        _z_zbuf_copy_bytes(&peer->flow_buff, &ztu->_common._zbuf);
        return _Z_RES_OK;
    }
    *message_to_process = true;
    return _Z_RES_OK;
}

static int _z_unicast_peer_read(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer, size_t *to_read) {
    // If we receive fragmented data we have to store it on a separate buffer
    size_t read_size = 0;
    switch (ztu->_common._link->_cap._flow) {
        case Z_LINK_CAP_FLOW_STREAM:
            switch (peer->flow_state) {
                case _Z_FLOW_STATE_READY:
                    peer->flow_state = _Z_FLOW_STATE_INACTIVE;
                    peer->flow_curr_size = 0;
                    _z_zbuf_clear(&peer->flow_buff);  // fall through
                default:                              // fall through
                case _Z_FLOW_STATE_INACTIVE:
                    read_size = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
                    if (read_size == 0) {
                        _Z_DEBUG("Socket closed");
                        return _Z_UNICAST_PEER_READ_STATUS_SOCKET_CLOSED;
                    } else if (read_size == SIZE_MAX) {
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    if (_z_zbuf_len(&ztu->_common._zbuf) < _Z_MSG_LEN_ENC_SIZE) {
                        peer->flow_state = _Z_FLOW_STATE_PENDING_SIZE;
                        peer->flow_curr_size = _z_zbuf_read(&ztu->_common._zbuf);
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    // Get stream size
                    *to_read = _z_read_stream_size(&ztu->_common._zbuf);
                    // Read data if needed
                    read_size = _z_zbuf_len(&ztu->_common._zbuf);
                    if (read_size < *to_read) {
                        peer->flow_state = _Z_FLOW_STATE_PENDING_DATA;
                        peer->flow_curr_size = (uint16_t)*to_read;
                        peer->flow_buff = _z_zbuf_make(peer->flow_curr_size);
                        if (_z_zbuf_capacity(&peer->flow_buff) != peer->flow_curr_size) {
                            _Z_ERROR("Not enough memory to allocate flow state buffer");
                            return _Z_UNICAST_PEER_READ_STATUS_CRITICAL_ERROR;
                        }
                        _z_zbuf_copy_bytes(&peer->flow_buff, &ztu->_common._zbuf);
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    break;
                case _Z_FLOW_STATE_PENDING_SIZE:
                    read_size = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
                    if (read_size == 0) {
                        _Z_DEBUG("Socket closed");
                        return _Z_UNICAST_PEER_READ_STATUS_SOCKET_CLOSED;
                    } else if (read_size == SIZE_MAX) {
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    peer->flow_curr_size += (uint16_t)(_z_zbuf_read(&ztu->_common._zbuf) << 8);
                    *to_read = peer->flow_curr_size;
                    if (_z_zbuf_len(&ztu->_common._zbuf) < *to_read) {
                        peer->flow_state = _Z_FLOW_STATE_PENDING_DATA;
                        peer->flow_buff = _z_zbuf_make(peer->flow_curr_size);
                        if (_z_zbuf_capacity(&peer->flow_buff) != peer->flow_curr_size) {
                            _Z_ERROR("Not enough memory to allocate flow state buffer");
                            return _Z_UNICAST_PEER_READ_STATUS_CRITICAL_ERROR;
                        }
                        _z_zbuf_copy_bytes(&peer->flow_buff, &ztu->_common._zbuf);
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    break;
                case _Z_FLOW_STATE_PENDING_DATA:
                    read_size = _z_link_socket_recv_zbuf(ztu->_common._link, &peer->flow_buff, peer->_socket);
                    if (read_size == 0) {
                        _Z_DEBUG("Socket closed");
                        return _Z_UNICAST_PEER_READ_STATUS_SOCKET_CLOSED;
                    } else if (read_size == SIZE_MAX) {
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    }
                    *to_read = peer->flow_curr_size;
                    if (_z_zbuf_len(&peer->flow_buff) < *to_read) {
                        return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
                    } else {
                        peer->flow_state = _Z_FLOW_STATE_READY;
                    }
                    break;
            }

            break;
        case Z_LINK_CAP_FLOW_DATAGRAM:
            *to_read = _z_link_socket_recv_zbuf(ztu->_common._link, &ztu->_common._zbuf, peer->_socket);
            if (*to_read == SIZE_MAX) {
                return _Z_UNICAST_PEER_READ_STATUS_PENDING_DATA;
            }
            break;
        default:
            break;
    }
    return _Z_UNICAST_PEER_READ_STATUS_OK;
}

static z_result_t _zp_unicast_process_peer_event(_z_transport_unicast_t *ztu) {
    _z_transport_peer_mutex_lock(&ztu->_common);
    _z_transport_peer_unicast_slist_t *curr_list = ztu->_peers;
    _z_transport_peer_unicast_slist_t *prev = NULL;
    _z_transport_peer_unicast_slist_t *prev_drop = NULL;
    size_t to_read = 0;
    while (curr_list != NULL) {
        bool drop_peer = false;
        _z_transport_peer_unicast_t *curr_peer = _z_transport_peer_unicast_slist_value(curr_list);
        if (curr_peer->_pending) {
            curr_peer->_pending = false;
            // Read data from socket
            int res = _z_unicast_peer_read(ztu, curr_peer, &to_read);
            if (res == _Z_UNICAST_PEER_READ_STATUS_OK) {  // Messages to process
                bool message_to_process = false;
                do {
                    message_to_process = false;
                    // Process one message
                    if (_z_unicast_process_messages(ztu, curr_peer, to_read) != _Z_RES_OK) {
                        // Failed to process, drop peer
                        _Z_ERROR("Dropping peer due to processing error");
                        drop_peer = true;
                        prev_drop = prev;
                        break;
                    } else if (curr_peer->flow_state != _Z_FLOW_STATE_READY) {
                        // Process remaining data
                        size_t extra_data = _z_zbuf_len(&ztu->_common._zbuf);
                        if (extra_data > 0) {
                            _Z_RETURN_IF_ERR(_z_unicast_handle_remaining_data(ztu, curr_peer, extra_data, &to_read,
                                                                              &message_to_process));
                        }
                    }
                } while (message_to_process);
            } else if (res == _Z_UNICAST_PEER_READ_STATUS_SOCKET_CLOSED) {
                drop_peer = true;
                prev_drop = prev;
            } else if (res == _Z_UNICAST_PEER_READ_STATUS_CRITICAL_ERROR) {
                _Z_ERROR_RETURN(_Z_ERR_SYSTEM_OUT_OF_MEMORY);
            }
        }
        // Update previous only if current node is not dropped
        if (!drop_peer) {
            prev = curr_list;
        }
        // Progress list
        curr_list = _z_transport_peer_unicast_slist_next(curr_list);
        // Drop peer if needed
        if (drop_peer) {
            _Z_DEBUG("Dropping peer");
            _z_session_t *zs = _z_transport_common_get_session(&ztu->_common);
            _z_subscription_cache_invalidate(zs);
            _z_queryable_cache_invalidate(zs);
            _z_interest_peer_disconnected(zs, &curr_peer->common);
            ztu->_peers = _z_transport_peer_unicast_slist_drop_element(ztu->_peers, prev_drop);
        }
        _z_zbuf_reset(&ztu->_common._zbuf);
    }
    _z_transport_peer_mutex_unlock(&ztu->_common);
    return _Z_RES_OK;
}

void *_zp_unicast_read_task(void *ztu_arg) {
    _z_transport_unicast_t *ztu = (_z_transport_unicast_t *)ztu_arg;

    // Acquire and keep the lock
    _z_mutex_lock(&ztu->_common._mutex_rx);

    // Prepare the buffer
    _z_zbuf_reset(&ztu->_common._zbuf);
    z_whatami_t mode = _z_transport_common_get_session(&ztu->_common)->_mode;
    _z_transport_peer_unicast_t *curr_peer = NULL;
    if (mode == Z_WHATAMI_CLIENT) {
        curr_peer = _z_transport_peer_unicast_slist_value(ztu->_peers);
        assert(curr_peer != NULL);
    }
    while (ztu->_common._read_task_running) {
        g_zp_loop++;  // INSTRUMENTACAO
#if Z_FEATURE_UNICAST_PEER == 1
        if (mode == Z_WHATAMI_PEER) {
            // Wait for at least one peer
            if (_z_transport_peer_unicast_slist_is_empty(ztu->_peers)) {
                z_sleep_s(1);
                continue;
            }
            // Wait for events on sockets (need mutex)
            if (_z_socket_wait_event(&ztu->_peers, &ztu->_common._mutex_peer) != _Z_RES_OK) {
                continue;  // Might need to process errors other than timeout
            }
            // Process events for all peers
            if (_zp_unicast_process_peer_event(ztu) != _Z_RES_OK) {
                ztu->_common._read_task_running = false;
                continue;
            }
        } else
#endif
        {
            size_t to_read = 0;
            // Retrieve data
            g_zp_recv_in++;  // INSTRUMENTACAO
            bool got = _z_unicast_client_read(ztu, curr_peer, &to_read);
            g_zp_recv_out++;  // INSTRUMENTACAO
            if (!got) {
                continue;
            }
            g_zp_recv_data++;  // INSTRUMENTACAO
            // Process data
            g_zp_proc_in++;  // INSTRUMENTACAO
            z_result_t pret = _z_unicast_process_messages(ztu, curr_peer, to_read);
            g_zp_proc_out++;  // INSTRUMENTACAO
            if (pret != _Z_RES_OK) {
                ztu->_common._read_task_running = false;
                continue;
            }
        }
    }
    _z_mutex_unlock(&ztu->_common._mutex_rx);
    return NULL;
}

z_result_t _zp_unicast_start_read_task(_z_transport_t *zt, z_task_attr_t *attr, _z_task_t *task) {
    // Init memory
    (void)memset(task, 0, sizeof(_z_task_t));
    zt->_transport._unicast._common._read_task_running = true;  // Init before z_task_init for concurrency issue
    // Init task
    if (_z_task_init(task, attr, _zp_unicast_read_task, &zt->_transport._unicast) != _Z_RES_OK) {
        zt->_transport._unicast._common._read_task_running = false;
        _Z_ERROR_RETURN(_Z_ERR_SYSTEM_TASK_FAILED);
    }
    // Attach task
    zt->_transport._unicast._common._read_task = task;
    return _Z_RES_OK;
}

z_result_t _zp_unicast_stop_read_task(_z_transport_t *zt) {
    zt->_transport._unicast._common._read_task_running = false;
    return _Z_RES_OK;
}

#else   // Z_FEATURE_MULTI_THREAD == 1 && Z_FEATURE_UNICAST_TRANSPORT == 1

void *_zp_unicast_read_task(void *ztu_arg) {
    _ZP_UNUSED(ztu_arg);
    return NULL;
}

z_result_t _zp_unicast_start_read_task(_z_transport_t *zt, void *attr, void *task) {
    _ZP_UNUSED(zt);
    _ZP_UNUSED(attr);
    _ZP_UNUSED(task);
    _Z_ERROR_RETURN(_Z_ERR_TRANSPORT_NOT_AVAILABLE);
}

z_result_t _zp_unicast_stop_read_task(_z_transport_t *zt) {
    _ZP_UNUSED(zt);
    _Z_ERROR_RETURN(_Z_ERR_TRANSPORT_NOT_AVAILABLE);
}
#endif  //  Z_FEATURE_MULTI_THREAD == 1 && Z_FEATURE_UNICAST_TRANSPORT == 1
