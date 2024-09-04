#ifndef OUI_LOOKUP_H
#define OUI_LOOKUP_H

#include <SD.h>  // SD Card library
#include <FS.h>  // Filesystem support for ESP32
#include <Arduino.h>  // Include Arduino library for String support

// Constants for Trie structure
#define ALPHABET_SIZE 16
#define OFFSET_SIZE 4
#define TRIE_NODE_SIZE 72

// TrieNode structure definition
struct TrieNode {
    int32_t children_offsets[ALPHABET_SIZE];  // Offsets to child nodes
    bool is_end_of_word;                      // Flag indicating if this node represents the end of an OUI
    int32_t manufacturer_offset;              // Offset to the manufacturer name in the file
};

// Function declarations

// Converts a hexadecimal character ('0'-'9', 'a'-'f') to its corresponding index (0-15)
int charToIndex(char ch);

// Function to read a node from the binary file at the given offset
TrieNode readNode(File &file, int32_t offset);

// Function to read the manufacturer name from the binary file at the given offset
String readManufacturerName(File &file, int32_t offset);

// Function to navigate the trie and find the manufacturer name for the given OUI
String findManufacturer(const char* filename, const String &oui);

#endif  // OUI_LOOKUP_H
