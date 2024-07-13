#include <Yboard.h>

#include "lab_wifi.h"

LabWiFiImp LabWiFi;

static bool *sniffed_packets;
static bool *sniffed_packet;
std::unordered_map<std::string, size_t> unique_macs;

void wifi_sniffer_rx_packet(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t header = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

    // // We only care about data packets
    // if (type != WIFI_PKT_DATA) {
    //     return;
    // }

    // Make sure we can parse the packet
    int len = pkt->rx_ctrl.sig_len;
    len -= sizeof(wifi_ieee80211_packet_t);
    if (len < -2) {
        Serial.println("Invalid packet length");
        return;
    }

    wifi_ieee80211_packet_t *wifi_pkt = (wifi_ieee80211_packet_t *)pkt->payload;

    // Copy mac addresses to strings
    char mac_addr_1[18];
    char mac_addr_2[18];
    char mac_addr_3[18];
    snprintf(mac_addr_1, sizeof(mac_addr_1), "%02X:%02X:%02X:%02X:%02X:%02X", wifi_pkt->addr1[0],
             wifi_pkt->addr1[1], wifi_pkt->addr1[2], wifi_pkt->addr1[3], wifi_pkt->addr1[4],
             wifi_pkt->addr1[5]);
    snprintf(mac_addr_2, sizeof(mac_addr_2), "%02X:%02X:%02X:%02X:%02X:%02X", wifi_pkt->addr2[0],
             wifi_pkt->addr2[1], wifi_pkt->addr2[2], wifi_pkt->addr2[3], wifi_pkt->addr2[4],
             wifi_pkt->addr2[5]);
    snprintf(mac_addr_3, sizeof(mac_addr_3), "%02X:%02X:%02X:%02X:%02X:%02X", wifi_pkt->addr3[0],
             wifi_pkt->addr3[1], wifi_pkt->addr3[2], wifi_pkt->addr3[3], wifi_pkt->addr3[4],
             wifi_pkt->addr3[5]);

    // Fill up the set with unique MAC addresses for each LED
    if (unique_macs.size() < 20) {
        unique_macs.insert(std::make_pair(mac_addr_1, unique_macs.size()));
        unique_macs.insert(std::make_pair(mac_addr_2, unique_macs.size()));
        unique_macs.insert(std::make_pair(mac_addr_3, unique_macs.size()));
    }

    // Update global variables with frame information
    *sniffed_packet = true;

    // Turn on LEDs for each unique MAC address
    auto it = unique_macs.find(mac_addr_1);
    if (it != unique_macs.end()) {
        sniffed_packets[it->second] = true;
    }
    it = unique_macs.find(mac_addr_2);
    if (it != unique_macs.end()) {
        sniffed_packets[it->second] = true;
    }
    it = unique_macs.find(mac_addr_3);
    if (it != unique_macs.end()) {
        sniffed_packets[it->second] = true;
    }
}

void LabWiFiImp::setup(const char *ssid, const char *password, bool *any_sniffed_packet,
                       bool packets[20]) {
    this->ssid = ssid;
    this->password = password;
    sniffed_packet = any_sniffed_packet;
    sniffed_packets = packets;
}

void LabWiFiImp::start_sniffer() {
    // Set up WiFi hardware
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_rx_packet));
}

void LabWiFiImp::stop_sniffer() {
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_stop());
}

void LabWiFiImp::start_client() {
    // Connect to the WiFi network
    Serial.printf("Connecting to WiFi network (%s)\n", ssid);

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED) {
        Yboard.set_all_leds_color(255, 255, 255);
        delay(250);
        Yboard.set_all_leds_color(0, 0, 0);
        delay(250);
        Serial.printf(".");
    }
}

void LabWiFiImp::stop_client() { WiFi.disconnect(true, true); }
