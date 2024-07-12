#include "Arduino.h"
#include "HTTPClient.h"
#include "colors.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "wifi_sniffing.h"
#include <ArduinoJson.h>
#include <StateMachine.h>
#include <WiFi.h>
#include <unordered_map>
#include <yboard.h>

static const String serverUrl = "http://ecen192.byu.edu:5000";

typedef struct {
    const char *id;
    const char *password;
} credentials_t;

void start_sniffer();
void stop_sniffer();
void start_client();
void stop_client();

// Callback for when a packet is received
void wifi_sniffer_rx_packet(void *buf, wifi_promiscuous_pkt_type_t type);

// State machine states
void sniff_all_state();
void sniff_individual_state();
void client_state();

bool get_credentials(credentials_t *credentials);
bool poll_server();

int current_channel = 1;
bool sniffed_packet = false;
int rssi = 0;
bool leds[20] = {false};
std::unordered_map<std::string, size_t> unique_macs;
bool client_connected = false;
bool sniffing = false;

credentials_t credentials = {NULL, NULL};

StateMachine machine = StateMachine();
State *SniffStateAll = machine.addState(&sniff_all_state);
State *SniffStateIndividual = machine.addState(&sniff_individual_state);
State *ClientState = machine.addState(&client_state);

void setup() {
    Serial.begin(9600);
    Yboard.setup();

    // Set up state machine transitions
    SniffStateAll->addTransition([]() { return Yboard.get_switch(1); }, SniffStateIndividual);
    SniffStateAll->addTransition([]() { return Yboard.get_switch(2); }, ClientState);

    SniffStateIndividual->addTransition([]() { return !Yboard.get_switch(1); }, SniffStateAll);
    SniffStateIndividual->addTransition([]() { return Yboard.get_switch(2); }, ClientState);

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

    WiFi.mode(WIFI_STA);
    WiFi.begin(SSID, PASSWORD);

    while (WiFi.status() != WL_CONNECTED) {
        Yboard.set_all_leds_color(255, 255, 255);
        delay(250);
        Yboard.set_all_leds_color(0, 0, 0);
        delay(250);
        Serial.printf(".");
    }
}

void stop_client() { WiFi.disconnect(true, true); }

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
            Serial.println("Stopping client and starting sniffer...");
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
            Serial.println("Stopping client and starting sniffer...");
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
            Serial.println("Stopping sniffer and starting client...");
            stop_sniffer();
            sniffing = false;
            delay(200);
            start_client();
        }

        // Set the lights to show that it is connected
        Yboard.set_all_leds_color(0, 0, 100);
        Serial.println(WiFi.localIP());
    }

    if (credentials.id == NULL || credentials.password == NULL) {
        // Get the ID and password from the server
        if (!get_credentials(&credentials)) {
            Serial.println("Error getting credentials from server");
        }
        // Wait for 5 seconds and then try again
        delay(5000);
        return;
    }

    // Send command to server
    poll_server();
    delay(2000);
}

bool poll_server() {
    HTTPClient http;
    http.begin(serverUrl + "/poll_commands");
    int httpResponseCode = http.GET();

    if (httpResponseCode != 200) {
        Serial.printf("Error: HTTP response code was not 200 (%d)\n", httpResponseCode);
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end(); // Close the connection

    JsonDocument doc;
    if (deserializeJson(doc, payload) != DeserializationError::Ok) {
        Serial.printf("Error: Could not parse server response\n");
        return false;
    }

    if (!doc.containsKey("command")) {
        Serial.printf("Error: Server response does not contain 'command'\n");
        return false;
    }

    String command = doc["command"];

    // Check the command and respond accordingly
    if (command == "change_led_color") {
        int r = doc["r"];
        int g = doc["g"];
        int b = doc["b"];

        Serial.printf("Changing LED color to (%d, %d, %d)\n", r, g, b);
        Yboard.set_all_leds_color(r, g, b);
        return true;
    } else {
        Serial.printf("Unknown command: %s\n", command.c_str());
        return false;
    }

    // Confirm that the command was executed
    //     confirmCommandExecuted(command);
    // } else if (command == "change_password") {
    //     String new_password = doc["new_password"].as<String>();
    //     printf("Changing password to %s\n", new_password.c_str());
    //     // Implement your password change logic here
    //     app_password = new_password;
    //     // Confirm that the command was executed
    //     confirmCommandExecuted(command);
    // } else {
    //     printf("Unknown command: %s\n", command.c_str());
    // }
}

bool get_credentials(credentials_t *credentials) {
    printf("Getting credentials from the server\n");

    HTTPClient http;
    http.begin(serverUrl + "/get_credentials");
    int httpResponseCode = http.GET();

    if (httpResponseCode != 200) {
        Serial.printf("Error: HTTP response code was not 200 (%d)\n", httpResponseCode);
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end(); // Close the connection
    Serial.println(payload);

    JsonDocument doc;
    if (deserializeJson(doc, payload) != DeserializationError::Ok) {
        Serial.printf("Error: Could not parse server response\n");
        return false;
    }

    if (doc.containsKey("identifier") && doc.containsKey("password")) {
        credentials->id = doc["identifier"];
        credentials->password = doc["password"];
        return true;
    } else {
        Serial.printf("Error: Server response does not contain 'identifier' or 'password'\n");
        return false;
    }
}
