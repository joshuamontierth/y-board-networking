#include "Arduino.h"
#include "HTTPClient.h"
#include "colors.h"
#include "lab_wifi.h"
#include <ArduinoJson.h>
#include <yboard.h>

static const String ssid = "BYU-WiFi";
static const String password = "";
static const String server_url = "http://ecen192.byu.edu:5000";

static bool station_mode = false;
static bool monitor_mode = false;

typedef struct {
    const char *id;
    const char *password;
} credentials_t;

bool get_credentials(credentials_t *credentials);
bool poll_server();

int sniffed_packet = 0;
int sniffed_packet_old = 0;
int leds[20] = {0};
int channel = 1;
unsigned long time_since_packet = 0;

credentials_t credentials = {NULL, NULL};

void set_channel_state() {
    set_display_lock(true);
    clear_display();
    while(Yboard.get_switch(1)) {
        display_text("Channel: " + std::to_string(channel), "Press button 1 to -", "Press button 2 to +");
        Yboard.set_all_leds_color(0, 0, 0);
        Yboard.set_led_color(channel, 255, 255, 255);
        if(Yboard.get_button(2)) {
            channel++;
            while(Yboard.get_button(2));
        }
        else if(Yboard.get_button(1)) {
            channel--;
            while(Yboard.get_button(1));
        }
        if (channel > 11) {
            channel = 1;
        }
        if (channel < 1) {
            channel = 11;
        }

    }
    set_display_lock(false);
    clear_display();
    LabWiFi.clear_mac_data();
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void setup() {
    Serial.begin(9600);
    Yboard.setup();
    LabWiFi.setup(ssid, password, &sniffed_packet, leds);
    time_since_packet = millis();
}

void loop() {
    

    if (Yboard.get_switch(2)) {
        if (!station_mode) {
            if (monitor_mode) {
                LabWiFi.stop_sniffer();
                monitor_mode = false;
                esp_restart();
            }

            LabWiFi.start_client();
            station_mode = true;
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

        poll_server();
        delay(2000);
        return;
    }

    if (sniffed_packet != sniffed_packet_old) {
        time_since_packet = millis();
    }
    else if (millis() - time_since_packet > 3000) {
        display_text("No packets sniffed", "", "Packets/sec: 0");
    }
    
    sniffed_packet_old = sniffed_packet;
    if (sniffed_packet == INT32_MAX) {
        sniffed_packet = 0;
    }
    

    if (!monitor_mode) {
        if (station_mode) {
            LabWiFi.stop_client();
            station_mode = false;
            esp_restart();
        }
        
        LabWiFi.start_sniffer();
        monitor_mode = true;
    }

    // Update brightness of LEDs based on knob
    int brightness = map(Yboard.get_knob(), 0, 100, 10, 255);
    Yboard.set_led_brightness(brightness);

    if (Yboard.get_switch(1)) {
        set_channel_state();
    } else {
        for (int i = 0; i < 18; i++) {
            int offset = i >= 13 ? 1 : 0;
            if (leds[i]) {
                
                Yboard.set_led_color(i + 1 + offset,red_to_blue(leds[i]).red, red_to_blue(leds[i]).green, red_to_blue(leds[i]).blue);
                leds[i] = 0;
            } else {
                Yboard.set_led_color(i + 1 + offset, 0, 0, 0);
            }
        }
    }
}

bool poll_server() {
    HTTPClient http;
    http.begin(server_url + "/poll_commands");
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
    }
    else if (command == "play_song") {
        String song = doc["song"];
        Yboard.play_sound_file(song.c_str());
        return true;
    }
    else {
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
    http.begin(server_url + "/get_credentials");
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

    if (doc.containsKey("ip_address") && doc.containsKey("password")) {
        credentials->id = doc["ip_address"];
        credentials->password = doc["password"];
        setup_display();
        display_text("IP: " + std::string(credentials->id), "Password: " + std::string(credentials->password), "");
        return true;
    } else {
        Serial.printf("Error: Server response does not contain 'identifier' or 'password'\n");
        return false;
    }
}


