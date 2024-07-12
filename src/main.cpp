#include "Arduino.h"
#include "colors.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "wifi_sniffing.h"
#include <StateMachine.h>
#include <WiFi.h>
#include <unordered_map>
#include <yboard.h>


void start_sniffer();
void stop_sniffer();
void start_client();
void stop_client();

// Callback for when a packet is received
void wifi_sniffer_rx_packet(void *buf, wifi_promiscuous_pkt_type_t type);

// State machine states
void sniff_all_state();
void sniff_individual_state();
void adjust_channel_state();
void increase_channel_state();
void decrease_channel_state();
void client_state();

int current_channel = 1;
bool sniffed_packet = false;
int rssi = 0;
bool leds[20] = {false};
std::unordered_map<std::string, size_t> unique_macs;
bool client_connected = false;
bool sniffing = false;
bool already_connected = false;

StateMachine machine = StateMachine();
State *SniffStateAll = machine.addState(&sniff_all_state);
State *SniffStateIndividual = machine.addState(&sniff_individual_state);
State *AdjustChannelState = machine.addState(&adjust_channel_state);
State *IncreaseChannelState = machine.addState(&increase_channel_state);
State *DecreaseChannelState = machine.addState(&decrease_channel_state);
State *ClientState = machine.addState(&client_state);

void setup() {
    Serial.begin(9600);
    Yboard.setup();

    // Set up state machine transitions
    SniffStateAll->addTransition([]() { return Yboard.get_switch(1); }, SniffStateIndividual);
    SniffStateAll->addTransition([]() { return Yboard.get_button(1); }, AdjustChannelState);
    SniffStateAll->addTransition([]() { return Yboard.get_switch(2); }, ClientState);

    SniffStateIndividual->addTransition([]() { return !Yboard.get_switch(1); }, SniffStateAll);
    SniffStateIndividual->addTransition([]() { return Yboard.get_button(1); }, AdjustChannelState);
    SniffStateIndividual->addTransition([]() { return Yboard.get_switch(2); }, ClientState);

    AdjustChannelState->addTransition(
        []() { return !Yboard.get_switch(1) && Yboard.get_button(1) && Yboard.get_button(2); },
        SniffStateAll);
    AdjustChannelState->addTransition(
        []() { return Yboard.get_switch(1) && Yboard.get_button(1) && Yboard.get_button(2); },
        SniffStateIndividual);
    AdjustChannelState->addTransition([]() { return Yboard.get_button(2); }, IncreaseChannelState);
    AdjustChannelState->addTransition([]() { return Yboard.get_button(1); }, DecreaseChannelState);

    IncreaseChannelState->addTransition([]() { return !Yboard.get_button(2); }, AdjustChannelState);

    DecreaseChannelState->addTransition([]() { return !Yboard.get_button(1); }, AdjustChannelState);

    ClientState->addTransition([]() { return !Yboard.get_switch(2) && !Yboard.get_switch(1); },
                               SniffStateAll);
    ClientState->addTransition([]() { return !Yboard.get_switch(2) && Yboard.get_switch(1); },
                               SniffStateIndividual);
}

void loop() { machine.run(); }

void start_sniffer() {
    // Set up WiFi hardware
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_rx_packet));
}

void stop_sniffer() {
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_stop());
}

void start_client() {
    // Connect to the WiFi network
    Serial.println("Connecting to WiFi network");

    if (!already_connected) {
        already_connected = true;
        WiFi.begin(SSID, PASSWORD);
    } else {
        WiFi.reconnect();
    }

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.printf(".");
    }
}

void stop_client() { WiFi.disconnect(false); }

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
    if (len < 0) {
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
    sniffed_packet = true;
    rssi = header.rssi;

    // Turn on LEDs for each unique MAC address
    auto it = unique_macs.find(mac_addr_1);
    if (it != unique_macs.end()) {
        leds[it->second] = true;
    }
    it = unique_macs.find(mac_addr_2);
    if (it != unique_macs.end()) {
        leds[it->second] = true;
    }
    it = unique_macs.find(mac_addr_3);
    if (it != unique_macs.end()) {
        leds[it->second] = true;
    }
}

void sniff_all_state() {
    // Only run this once
    if (machine.executeOnce) {
        if (!sniffing) {
            stop_client();
            delay(200);
            start_sniffer();
            sniffing = true;
        }

        // Update WiFi channel
        Serial.printf("Switching to channel %d\n", current_channel);
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
        delay(200);
    }

    // Update brightness of LEDs based on knob
    int brightness = map(Yboard.get_knob(), 0, 100, 0, 255);
    Yboard.set_led_brightness(brightness);

    // If the first switch is set, blink the LEDs for every frame sniffed
    if (sniffed_packet) {
        sniffed_packet = false;

        // Map RSSI to 0 and 255
        int value = map(rssi, -90, -65, 0, 255);

        // Map value to rainbow color
        RGBColor color = color_wheel(value);

        // Light up LEDs
        Yboard.set_all_leds_color(color.red, color.green, color.blue);
    } else {
        // Turn off LEDs
        Yboard.set_all_leds_color(0, 0, 0);
    }

    // Serial.println("Done with sniff all state");
    // Serial.printf("%d, %d\n", Yboard.get_button(1), Yboard.get_button(2));
}

void sniff_individual_state() {
    // Only run this once
    if (machine.executeOnce) {
        if (!sniffing) {
            stop_client();
            delay(200);
            start_sniffer();
            sniffing = true;
        }

        // Update WiFi channel
        Serial.printf("Switching to channel %d\n", current_channel);
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);

        unique_macs.clear();
        delay(200);
    }

    // Update brightness of LEDs based on knob
    int brightness = map(Yboard.get_knob(), 0, 100, 0, 255);
    Yboard.set_led_brightness(brightness);

    for (int i = 0; i < 20; i++) {
        if (leds[i]) {
            Yboard.set_led_color(i + 1, 255, 255, 255);
            leds[i] = false;
        } else {
            Yboard.set_led_color(i + 1, 0, 0, 0);
        }
    }
}

void client_state() {
    if (machine.executeOnce) {
        // Make sure no lights are still on from the previous state
        Yboard.set_all_leds_color(0, 0, 0);

        if (sniffing) {
            stop_sniffer();
            sniffing = false;
            delay(200);
            start_client();
        }
    }

    Serial.println(WiFi.localIP());
    delay(500);
}

void adjust_channel_state() {
    // Only run this state once
    if (!machine.executeOnce) {
        delay(200);
        return;
    }
    Serial.println("Adjust channel state");

    // Light up the LEDs based on the current channel
    for (int i = 1; i < Yboard.led_count + 1; i++) {
        if (i <= current_channel) {
            Yboard.set_led_color(i, 255, 255, 255);
        } else {
            Yboard.set_led_color(i, 0, 0, 0);
        }
    }
}

void increase_channel_state() {
    // Only run this state once
    if (!machine.executeOnce) {
        delay(200);
        return;
    }
    Serial.println("Increase channel state");

    current_channel++;
    if (current_channel > 11) {
        current_channel = 11;
    }
}

void decrease_channel_state() {
    // Only run this state once
    if (!machine.executeOnce) {
        delay(200);
        return;
    }
    Serial.println("Decrease channel state");

    current_channel--;
    if (current_channel < 1) {
        current_channel = 1;
    }
}
