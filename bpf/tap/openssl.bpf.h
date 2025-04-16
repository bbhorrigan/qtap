/*
 * This code runs using libbpf in the Linux kernel.
 * Copyright 2025 - The Qpoint Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#pragma once

#include "vmlinux.h"

/*
 * This file provides a generic interface for TLS implementations to register
 * themselves with OpenSSL. For example, instead of OpenSSL directly calling
 * NodeTLS functions, NodeTLS can register its presence with OpenSSL through this
 * interface.
 */

// Helper functions that OpenSSL will call
static inline int ssl_register_handle(uintptr_t ssl) {
#ifdef ENABLE_NODETLS
	// Call into the NodeTLS module using the extern declaration
	extern int update_node_ssl_tls_wrap_map(uintptr_t ssl);
	return update_node_ssl_tls_wrap_map(ssl);
#else
	return 0;
#endif
}

static inline int32_t ssl_get_fd(uint64_t pid_tgid, uintptr_t ssl) {
#ifdef ENABLE_NODETLS
	// Call into the NodeTLS module using the extern declaration
	extern int32_t get_fd_from_node(uint64_t pid_tgid, uintptr_t ssl);
	return get_fd_from_node(pid_tgid, ssl);
#else
	return 0;
#endif
}

static inline int ssl_remove_handle(uintptr_t ssl) {
#ifdef ENABLE_NODETLS
	// Call into the NodeTLS module using the extern declaration
	extern int remove_node_ssl_tls_wrap_map(uintptr_t ssl);
	return remove_node_ssl_tls_wrap_map(ssl);
#else
	return 0;
#endif
}
