//
// Copyright (c) 2024 ZettaScale Technology
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

#include "zenoh-pico/transport/transport.h"

#include <stdbool.h>

#include "zenoh-pico/link/link.h"
#include "zenoh-pico/system/common/platform.h"
#include "zenoh-pico/transport/unicast/accept.h"
#include "zenoh-pico/utils/result.h"

void _z_common_transport_clear(_z_transport_common_t *ztc, bool detach_tasks) {
#if Z_FEATURE_MULTI_THREAD == 1
    // Clean up tasks
    if (ztc->_read_task != NULL) {
        ztc->_read_task_running = false;
        // ALWAYS join, never detach, regardless of `detach_tasks`. That flag exists so a
        // task can avoid joining ITSELF (the lease task calls this function on itself via
        // _zp_unicast_failed -> _z_unicast_transport_clear(ztu, true)); the read task never
        // calls this function, so joining it from here is always safe and never self-joins.
        //
        // Detaching it here used to race: right below, this function destroys _mutex_rx and
        // frees _link/_zbuf/_wbuf, all of which the (merely detached, not guaranteed-exited)
        // read task thread could still be using -- destroying a mutex another thread holds
        // locked, and freeing a link/buffer it's still reading from, is undefined behavior.
        // The read task's own loop (read.c) only exits by checking _read_task_running, and on
        // a dead peer it does so on every iteration without blocking (see the sleep added in
        // read.c for why that loop used to spin instead of blocking), so this join returns
        // essentially immediately in the common case and is bounded by the socket's
        // SO_RCVTIMEO otherwise -- never open-ended.
        _z_task_join(ztc->_read_task);
        _z_task_free(&ztc->_read_task);
        ztc->_read_task = NULL;
    }
    if (ztc->_lease_task != NULL) {
        ztc->_lease_task_running = false;
        if (detach_tasks) {
            _z_task_detach(ztc->_lease_task);
        } else {
            _z_task_join(ztc->_lease_task);
        }
        _z_task_free(&ztc->_lease_task);
        ztc->_lease_task = NULL;
    }
    _zp_unicast_stop_accept_task(ztc);

    // Clean up the mutexes
    _z_mutex_drop(&ztc->_mutex_tx);
    _z_mutex_drop(&ztc->_mutex_rx);
    _z_mutex_rec_drop(&ztc->_mutex_peer);
#else
    _ZP_UNUSED(detach_tasks);
#endif  // Z_FEATURE_MULTI_THREAD == 1

    // Clean up the buffers
    _z_wbuf_clear(&ztc->_wbuf);
    _z_zbuf_clear(&ztc->_zbuf);

    _z_link_free(&ztc->_link);
    _z_session_weak_drop(&ztc->_session);
}
