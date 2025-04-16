#pragma once

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "tap.bpf.h"
#include "socket.bpf.h"

// this map allows a process to find the underlying socket from fd
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct pid_fd_key); // the file pointer
	__type(value, uintptr_t); // the socket pointer
} pid_fd_to_sock_map SEC(".maps");

// this map allows a socket program to find the pid from the address and port
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct addr_port_key); // the address and port
	__type(value, uint32_t); // the pid
} addr_port_to_pid_map SEC(".maps");
