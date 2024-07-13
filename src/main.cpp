#include "Arduino.h"
#include "HTTPClient.h"
#include "colors.h"
#include "lab_wifi.h"
#include <ArduinoJson.h>
#include <yboard.h>

#define SSID ""
#define PASSWORD ""

static const String serverUrl = "http://ecen192.byu.edu:5000";

typedef struct {
    const char *id;
    const char *password;
} credentials_t;

static bool station_mode = false;
static bool monitor_mode = false;

bool get_credentials(credentials_t *credentials);
bool poll_server();

int current_channel = 1;
bool sniffed_packet = false;
bool leds[20] = {false};

credentials_t credentials = {NULL, NULL};

void setup() {
    Serial.begin(9600);
    Yboard.setup();
    LabWiFi.setup("", "", &sniffed_packet, leds);
}

void loop() {
    if (Yboard.get_switch(2)) {
        if (!station_mode) {
            LabWiFi.stop_sniffer();
            monitor_mode = false;

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

    if (!monitor_mode) {
        LabWiFi.stop_client();
        station_mode = false;

        LabWiFi.start_sniffer();
        monitor_mode = true;
    }

    // Update brightness of LEDs based on knob
    int brightness = map(Yboard.get_knob(), 0, 100, 0, 255);
    Yboard.set_led_brightness(brightness);

    if (Yboard.get_switch(1)) {
        // If the first switch is set, blink the LEDs for every frame sniffed
        if (sniffed_packet) {
            sniffed_packet = false;

            // Light up LEDs
            Yboard.set_all_leds_color(255, 255, 255);
        } else {
            // Turn off LEDs
            Yboard.set_all_leds_color(0, 0, 0);
        }
    } else {
        for (int i = 0; i < 20; i++) {
            if (leds[i]) {
                Yboard.set_led_color(i + 1, 255, 255, 255);
                leds[i] = false;
            } else {
                Yboard.set_led_color(i + 1, 0, 0, 0);
            }
        }
    }
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
