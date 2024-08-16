#ifndef COLORS_H
#define COLORS_H

#include <stdint.h>

typedef struct {
    unsigned char red;
    unsigned char green;
    unsigned char blue;
} RGBColor;

RGBColor color_wheel(uint8_t wheel_pos);

RGBColor red_to_blue(int redShade);

#endif /* COLORS_H */
