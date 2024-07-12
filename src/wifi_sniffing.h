#include <stdint.h>

typedef struct {
    int16_t frame_ctrl;
    int16_t duration_id;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    int16_t sequence_ctrl;
    unsigned char payload[];
} __attribute__((packed)) wifi_ieee80211_packet_t;

typedef struct {
    uint8_t version : 2;
    uint8_t type : 2;
    uint8_t subtype : 4;
    uint8_t to_ds : 1;
    uint8_t from_ds : 1;
    uint8_t more_frag : 1;
    uint8_t retry : 1;
    uint8_t pwr_mgt : 1;
    uint8_t more_data : 1;
    uint8_t protected_frame : 1;
    uint8_t order : 1;
} frame_ctrl_t;
