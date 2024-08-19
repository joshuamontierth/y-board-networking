#include "oui_lookup.h"
#include <unordered_map>
#include <string>


std::unordered_map<int, String> cached_lookups;

// Converts a hexadecimal character ('0'-'9', 'a'-'f') to its corresponding index (0-15)
int charToIndex(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else {
        // Handle invalid characters
        return -1;
    }
}

// Function to read a node from the binary file at the given offset
TrieNode readNode(File &file, int32_t offset) {
    TrieNode node;
    file.seek(offset);
    file.read((uint8_t*)&node, TRIE_NODE_SIZE);  // Read the node data from the file
    return node;
}

// Function to read the manufacturer name from the binary file at the given offset
String readManufacturerName(File &file, int32_t offset) {
    file.seek(offset);
    return file.readStringUntil('\0');  // Read until null terminator
}

// Function to navigate the trie and find the manufacturer name for the given OUI
String findManufacturer(const char* filename, const String &oui) {
    
    File file = SD.open(filename, FILE_READ);
    int decimalValue = std::stoi(oui.c_str(), nullptr, 16); 
    if (cached_lookups.find(decimalValue) != cached_lookups.end()) {
        return cached_lookups[decimalValue];
    }
    if (!file) {
        Serial.println("Failed to open file");
        return "";
    }

    int32_t current_offset = 0;  // Start at the root node (offset 0)
    
    // Navigate through the trie based on each character in the OUI
    for (int i = 0; i < oui.length(); i++) {
        char ch = tolower(oui.charAt(i));  
        int index = charToIndex(ch);
        if (index == -1) {
            Serial.println("Invalid character in OUI");
            return "";
        }

        // Read the current node from the file
        TrieNode current_node = readNode(file, current_offset);

        // Check if the child for this character exists (offset not -1)
        if (current_node.children_offsets[index] == -1) {
            Serial.println("OUI not found in trie");
            return "";
        }

        // Move to the next node
        current_offset = current_node.children_offsets[index];
    }

    // Read the final node to check if it marks the end of a word (valid OUI)
    TrieNode final_node = readNode(file, current_offset);
    

    if (final_node.is_end_of_word) {
        // If it's the end of a word, fetch the manufacturer name using the manufacturer_offset
        String manufacturer =  readManufacturerName(file, final_node.manufacturer_offset);
        if (ESP.getFreeHeap() < 500) {
            cached_lookups.clear();
        }
        cached_lookups[decimalValue] = manufacturer;
    }

    Serial.println("OUI found, but not an end of a valid manufacturer prefix");
    return "";
}