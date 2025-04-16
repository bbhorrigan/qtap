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
#include "bpf_tracing.h"

// flag definitions (matching the Go constants)
#define SKIP_DATA_FLAG (1 << 0)
#define SKIP_DNS_FLAG  (1 << 1)
#define SKIP_TLS_FLAG  (1 << 2)
#define SKIP_HTTP_FLAG (1 << 3)

// all flags
#define SKIP_ALL_FLAGS (SKIP_DATA_FLAG | SKIP_DNS_FLAG | SKIP_TLS_FLAG | SKIP_HTTP_FLAG)

enum QPOINT_STRATEGY {
	QP_OBSERVE,
	QP_IGNORE,
	QP_AUDIT,
	QP_FORWARD,
	QP_PROXY,
};

// any process meta available to Qtap that can be helpful within eBPF
struct process_meta {
	__u64 root_id; // 8 bytes
	__u32 qpoint_strategy; // 4 bytes
	__u8 filter; // 1 byte
	bool tls_ok; // 1 byte
	char container_id[13]; // 13 bytes
	char _pad[3]; // 3 bytes padding to maintain 8-byte alignment
};

static __always_inline struct process_meta *get_process_meta(__u32 pid);

// macros for checking individual flags
#define SKIP_DATA(pid) \
	({ \
		struct process_meta *meta = get_process_meta(pid); \
		(bool)((pid == qpid) || (meta && (meta->filter & SKIP_DATA_FLAG))); \
	})
#define SKIP_DNS(pid) \
	({ \
		struct process_meta *meta = get_process_meta(pid); \
		(bool)(meta && (meta->filter & SKIP_DNS_FLAG)); \
	})
#define SKIP_TLS(pid) \
	({ \
		struct process_meta *meta = get_process_meta(pid); \
		(bool)(meta && (meta->filter & SKIP_TLS_FLAG)); \
	})
#define SKIP_HTTP(pid) \
	({ \
		struct process_meta *meta = get_process_meta(pid); \
		(bool)(meta && (meta->filter & SKIP_HTTP_FLAG)); \
	})

// macro for checking all flags
#define SKIP_ALL(pid) \
	({ \
		struct process_meta *meta = get_process_meta(pid); \
		(bool)(meta && ((meta->filter & (SKIP_ALL_FLAGS & ~SKIP_DATA_FLAG)) == (SKIP_ALL_FLAGS & ~SKIP_DATA_FLAG)) && SKIP_DATA(pid)); \
	})