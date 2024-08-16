#ifndef LABWIFI_H
#define LABWIFI_H

#include <WiFi.h>
#include <set>
#include <stdint.h>
#include <unordered_map>

#include "esp_wifi.h"
#include "esp_wifi_types.h"

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


bool setup_display();
void display_text(const std::string &text_1,const std::string &text_2,const std::string &text_3);
void clear_display();
void set_display_lock(bool lock);


class LabWiFiImp {
  public:
    void setup(const char *ssid, const char *password, int *any_sniffed_packet,
               int sniffed_packets[20]);
    void setup(const String &ssid, const String &password, int *any_sniffed_packet,
               int sniffed_packets[20]);
    void setup(const std::string &ssid, const std::string &password, int *any_sniffed_packet,
               int sniffed_packets[20]);
    void start_sniffer();
    void stop_sniffer();
    void start_client();
    void stop_client();
    void clear_mac_data();
   

  private:
    const char *ssid;
    const char *password;
    
};

extern LabWiFiImp LabWiFi;

#endif
