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

#include "bpf_endian.h"

// Address family
#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// Sock
#define SO_ORIGINAL_DST 80
#define SO_MARK         36
#define SO_COOKIE       57

// A simplified representation of the network address
// This structure and supporting function assume network byte order
struct net_addr {
	// Address family (AF_INET or AF_INET6)
	uint16_t sa_family;
	// Minimum size to hold a IPv6 address. If IPv4 then the address will be found in the first four bytes
	uint8_t addr[16];
	// The address port
	uint16_t port;
};

// determine if ip address is local (127.0.0.1 etc)
// This function assumes the input address is in network byte order
static inline int is_local_ip(struct net_addr *addr) {
	if (addr->sa_family == AF_INET) {
		// ipv4 address
		__be32 ip = *(__be32 *)addr->addr;

		// check for loopback (127.0.0.0/8)
		if ((ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000)) {
			return 1;
		}

		// check for link-local (169.254.0.0/16)
		if ((ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xA9FE0000)) {
			return 1;
		}

		// check for 0.0.0.0 (used to indicate "any" local address)
		if (ip == 0) {
			return 1;
		}

	} else if (addr->sa_family == AF_INET6) {
		// check for ipv6 loopback (::1)
		if (addr->addr[0] == 0 && addr->addr[1] == 0 && addr->addr[2] == 0 && addr->addr[3] == 0 && addr->addr[4] == 0 && addr->addr[5] == 0 &&
			addr->addr[6] == 0 && addr->addr[7] == 0 && addr->addr[8] == 0 && addr->addr[9] == 0 && addr->addr[10] == 0 && addr->addr[11] == 0 &&
			addr->addr[12] == 0 && addr->addr[13] == 0 && addr->addr[14] == 0 && addr->addr[15] == 1) {
			return 1;
		}

		// check for IPv6 unspecified address (::)
		if (addr->addr[0] == 0 && addr->addr[1] == 0 && addr->addr[2] == 0 && addr->addr[3] == 0 && addr->addr[4] == 0 && addr->addr[5] == 0 &&
			addr->addr[6] == 0 && addr->addr[7] == 0 && addr->addr[8] == 0 && addr->addr[9] == 0 && addr->addr[10] == 0 && addr->addr[11] == 0 &&
			addr->addr[12] == 0 && addr->addr[13] == 0 && addr->addr[14] == 0 && addr->addr[15] == 0) {
			return 1;
		}

		// IPv4-mapped 127.0.0.0/8
		if (addr->addr[0] == 0 && addr->addr[1] == 0 && addr->addr[2] == 0 && addr->addr[3] == 0 && addr->addr[4] == 0 && addr->addr[5] == 0 &&
			addr->addr[6] == 0 && addr->addr[7] == 0 && addr->addr[8] == 0 && addr->addr[9] == 0 && addr->addr[10] == 0xff &&
			addr->addr[11] == 0xff && addr->addr[12] == 0x7f) {
			return 1;
		}
	}

	// not a local IP
	return 0;
}

// determine if ip address is public (external) or private
// This function assumes the input address is in network byte order
static inline int is_private_ip(struct net_addr *addr) {
	if (addr->sa_family == AF_INET) {
		// IPv4 checks
		__be32 ip = *(__be32 *)addr->addr;

		// check for 10.0.0.0/8
		if ((ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000)) {
			return 1;
		}

		// check for 172.16.0.0/12
		if ((ip & bpf_htonl(0xFFF00000)) == bpf_htonl(0xAC100000)) {
			return 1;
		}

		// check for 192.168.0.0/16
		if ((ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xC0A80000)) {
			return 1;
		}

	} else if (addr->sa_family == AF_INET6) {
		// check for Unique Local Address (ULA)
		if ((addr->addr[0] & 0xFE) == 0xFC) {
			return 1;
		}

		// check for Link-Local Address
		if (addr->addr[0] == 0xFE && (addr->addr[1] & 0xC0) == 0x80) {
			return 1;
		}

		// check for IPv4-mapped IPv6 address
		if (addr->addr[0] == 0 && addr->addr[1] == 0 && addr->addr[2] == 0 && addr->addr[3] == 0 && addr->addr[4] == 0 && addr->addr[5] == 0 &&
			addr->addr[6] == 0 && addr->addr[7] == 0 && addr->addr[8] == 0 && addr->addr[9] == 0 && addr->addr[10] == 0xFF &&
			addr->addr[11] == 0xFF) {
			__be32 ip = *(__be32 *)(&addr->addr[12]);

			// check for 10.0.0.0/8
			if ((ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000)) {
				return 1;
			}

			// check for 172.16.0.0/12
			if ((ip & bpf_htonl(0xFFF00000)) == bpf_htonl(0xAC100000)) {
				return 1;
			}

			// check for 192.168.0.0/16
			if ((ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xC0A80000)) {
				return 1;
			}
		}
	}

	// not a private IP
	return 0;
}
