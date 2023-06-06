#include <stdio.h>
#include "mac.h"

// fixed parmeter size of beacon frame
#define FIXED_PARAM_SIZE 12

typedef struct ieee80211_frame {
    u_int8_t frame_control[2];   // Frame control field
    u_int16_t duration_id;       // Duration/ID field
    Mac dst_mac;           // Address 1 (Destination MAC address)
    Mac src_mac;           // Address 2 (Source MAC address)
    Mac bssid;           // Address 3 (BSSID/MAC address of the access point)
    u_int16_t seq_ctrl;          // Sequence control field
    // Additional fields can follow depending on the frame type
} __attribute__((__packed__)) beacon_frame_t;

typedef struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
    /* radiotap data fields */
    u_int8_t        mac_timestamp[8];
    u_int8_t        flags;
    u_int8_t        rate;
    u_int16_t       channel_frequency;
    u_int16_t       channel_flags;
    u_int8_t        dbm_antenna_signal;
    u_int8_t        dbm_antenna_noise;
} __attribute__((__packed__)) radiotap_header_t;

typedef struct ieee80211_rsn {
    u_int16_t version;
    u_int32_t group_cipher_suite;
    u_int16_t pairwise_cipher_count;
} __attribute__((__packed__)) rsn_hdr_t;