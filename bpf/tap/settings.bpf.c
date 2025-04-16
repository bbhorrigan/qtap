#include "settings.bpf.h"

// extract the capture direction from settings
static __always_inline bool get_ignore_loopback_setting() {
	// define the settings key
	enum SOCKET_SETTINGS key = SOCK_SETTING_IGNORE_LOOPBACK;

	// init setting value
	__u32 *setting_value;

	// try to fetch the entry
	setting_value = bpf_map_lookup_elem(&socket_settings_map, &key);

	// if it's empty, return the default
	if (setting_value == NULL) {
		// bpf_printk("socket: get_ignore_loopback_setting = NULL");
		return false;
	}

	// debug
	// bpf_printk("socket: get_ignore_loopback_setting = %d", *setting_value);

	// return the value
	return (bool)*setting_value != 0;
}

// extract the capture direction from settings
static __always_inline enum DIRECTION get_direction_setting() {
	// define the settings key
	enum SOCKET_SETTINGS key = SOCK_SETTING_DIRECTION;

	// init setting value
	__u32 *setting_value;

	// try to fetch the entry
	setting_value = bpf_map_lookup_elem(&socket_settings_map, &key);

	// if it's empty, return the default
	if (setting_value == NULL) {
		// bpf_printk("socket: get_direction_setting = NULL");
		return D_ALL;
	}

	// debug
	// bpf_printk("socket: get_direction_setting = %d", *setting_value);

	// return the value
	return (enum DIRECTION) * setting_value;
}

// extract the stream http setting
static __always_inline bool get_stream_http_setting() {
	// define the settings key
	enum SOCKET_SETTINGS key = SOCK_SETTING_STREAM_HTTP;

	// init setting value
	__u32 *stream_http;

	// try to fetch the entry
	stream_http = bpf_map_lookup_elem(&socket_settings_map, &key);

	// if it's empty, return the default
	if (stream_http == NULL) {
		// bpf_printk("socket: get_ignore_loopback_setting = NULL");
		return false;
	}

	// debug
	// bpf_printk("socket: get_ignore_loopback_setting = %d", *stream_http);

	// return the value
	return (bool)*stream_http != 0;
}
