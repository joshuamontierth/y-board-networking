#include "colors.h"

RGBColor color_wheel(uint8_t wheel_pos) {
    RGBColor result;

    if (wheel_pos < 85) {
        result.red = wheel_pos * 3;
        result.green = 255 - wheel_pos * 3;
        result.blue = 0;
    } else if (wheel_pos < 170) {
        wheel_pos -= 85;
        result.red = 255 - wheel_pos * 3;
        result.green = 0;
        result.blue = wheel_pos * 3;
    } else {
        wheel_pos -= 170;
        result.red = 0;
        result.green = wheel_pos * 3;
        result.blue = 255 - wheel_pos * 3;
    }

    return result;
}

RGBColor blue_to_red(int blueShade) {
    RGBColor result;

    // Ensure that the blueShade is within the valid range (0-255)
    if (blueShade < 0) {
        blueShade = 0;
    } else if (blueShade > 255) {
        blueShade = 255;
    }

    // Map blue to red (assuming pure blue to pure red transition)
    result.red = 255 - blueShade;
    result.green = 0;
    result.blue = blueShade;

    return result;
}
