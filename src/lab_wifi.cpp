#include <yboard.h>
#include "lab_wifi.h"
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <unordered_map>
#include <deque>
#include "oui_lookup.h"

LabWiFiImp LabWiFi;

static int *sniffed_packets;
static int *sniffed_packet;
std::unordered_map<std::string, size_t> unique_macs;
std::deque<std::string> mac_queue;
Adafruit_SSD1306 display;
bool display_setup = false;
int rssi = 0;

int packet_count = 0;
unsigned long start_time = 0;
char packet_rate[20];
bool display_lock = false;


void set_display_lock(bool lock) {
    display_lock = lock;
}

bool setup_display() {
    if (display_setup) {
        return true;
    }
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3c)) {
        return false;
    } 
    display.clearDisplay();
    display.setTextColor(1);
    display.setRotation(0); 
    display.setTextWrap(false);
    display.display();
    display_setup = true;
    return true;
}

void display_text(const std::string &text_1, const std::string &text_2, const std::string &text_3) {
    unsigned long current_time = millis();
    
    if (current_time - start_time >= 400 || display_lock) {
        display.setTextSize(1);
        display.clearDisplay();
        display.setCursor(0, 0);
        display.print(text_1.c_str());
        display.setCursor(0, 10);
        display.print(text_2.c_str());
        display.setCursor(0, 20);
        display.print(text_3.c_str());
        display.display();
    }
    
}

void clear_display() {
    display.clearDisplay();
    display.display();
}



void wifi_sniffer_rx_packet(void *buf, wifi_promiscuous_pkt_type_t type) {
    // We only care about data packets
    if (type != WIFI_PKT_DATA) {
        return;
    }
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t header = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
    rssi = map(header.rssi, -90, -40, 0, 255);

    

    packet_count++;
    
    unsigned long current_time = millis();
    if (current_time - start_time >= 1000) {
        sprintf(packet_rate, "Packets/sec: %d", packet_count);
        packet_count = 0;
        start_time = current_time;
    }

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

    snprintf(mac_addr_1, sizeof(mac_addr_1), "%02X:%02X:%02X:%02X:%02X:%02X", wifi_pkt->addr2[0],
             wifi_pkt->addr2[1], wifi_pkt->addr2[2], wifi_pkt->addr2[3], wifi_pkt->addr2[4],
             wifi_pkt->addr2[5]);
    snprintf(mac_addr_2, sizeof(mac_addr_2), "%02X:%02X:%02X:%02X:%02X:%02X", wifi_pkt->addr3[0],
             wifi_pkt->addr3[1], wifi_pkt->addr3[2], wifi_pkt->addr3[3], wifi_pkt->addr3[4],
             wifi_pkt->addr3[5]);

    char oui_1[7];
    char oui_2[7];

    // to extract OUI from MAC address
    auto extractOUI = [](const char *mac, char *oui) {
        int j = 0;
        for (int i = 0; i < 9; ++i) { // 9 because "xx:xx:xx"
            if (mac[i] != ':') {
                oui[j++] = mac[i];
            }
        }
        oui[6] = '\0';
    };

    extractOUI(mac_addr_1, oui_1);
    extractOUI(mac_addr_2, oui_2);


    String content_1, content_2;
    if (SD.exists("/sd_card/ouis.jmt")) {
        content_1 = findManufacturer("/sd_card/ouis.jmt", oui_1);
        content_2 = findManufacturer("/sd_card/ouis.jmt", oui_2);
    }
    else {
        content_1 = "OUI Lookup";
        content_2 = "not available";
    }
    
    
    
    if (!display_lock) {
        display_text(content_1.c_str(), content_2.c_str(), packet_rate);
    }

    // Update the deque and map with unique MAC addresses for each LED
    auto update_unique_macs = [&](const std::string &mac_addr) {
        if (unique_macs.find(mac_addr) == unique_macs.end()) {
            size_t old_index = unique_macs.size();
            if (mac_queue.size() >= 18) {
                
                std::string oldest_mac = mac_queue.front();
                mac_queue.pop_front();
                old_index = unique_macs[oldest_mac];
                unique_macs.erase(oldest_mac);
            }
            mac_queue.push_back(mac_addr);
            unique_macs[mac_addr] = old_index;
        }
    };

    update_unique_macs(mac_addr_1);
    update_unique_macs(mac_addr_2);

    // Update global variables with frame information
    (*sniffed_packet)++;

    // Turn on LEDs for each unique MAC address
    auto it = unique_macs.find(mac_addr_1);
    if (it != unique_macs.end()) {
        sniffed_packets[it->second] = rssi;
    }
    it = unique_macs.find(mac_addr_2);
    if (it != unique_macs.end()) {
        sniffed_packets[it->second] = rssi;
    }


}

void LabWiFiImp::setup(const String &ssid, const String &password, int *any_sniffed_packet,
                       int packets[20]) {
    setup(ssid.c_str(), password.c_str(), any_sniffed_packet, packets);
}

void LabWiFiImp::setup(const std::string &ssid, const std::string &password,
                       int *any_sniffed_packet, int packets[20]) {
    setup(ssid.c_str(), password.c_str(), any_sniffed_packet, packets);
}

void LabWiFiImp::setup(const char *ssid, const char *password, int *any_sniffed_packet,
                       int packets[20]) {
    this->ssid = ssid;
    this->password = password;
    sniffed_packet = any_sniffed_packet;
    sniffed_packets = packets;
}

void LabWiFiImp::start_sniffer() {
    if (!setup_display()) {
        while (true) {
            Serial.println("Failed to initialize display");
            delay(1000);
        }
    }

    // Set up WiFi hardware
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    // set buffer sizes
    cfg.static_rx_buf_num = 4;
    cfg.dynamic_rx_buf_num = 4;
    cfg.static_tx_buf_num = 4;
    cfg.dynamic_tx_buf_num = 4;
    cfg.cache_tx_buf_num = 4;

    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        Serial.printf("WiFi init failed: %s\n", esp_err_to_name(err));
        return;
    }

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_rx_packet));

    packet_count = 0;
    start_time = millis();
}

void LabWiFiImp::stop_sniffer() {
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_stop());
}

void LabWiFiImp::start_client() {
    // Connect to the WiFi network
    while (WiFi.status() != WL_CONNECTED) {
        Serial.printf("Connecting to WiFi network (%s)\n", ssid);

        WiFi.mode(WIFI_STA);
        WiFi.begin(ssid, password);

        Yboard.set_all_leds_color(255, 255, 255);
        delay(250);
        Yboard.set_all_leds_color(0, 0, 0);
        delay(250);
        Serial.printf(".");
    }
}

void LabWiFiImp::stop_client() {
    WiFi.disconnect(true, true);
}

void LabWiFiImp::clear_mac_data() {
    unique_macs.clear();
    mac_queue.clear();
}

