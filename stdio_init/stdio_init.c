/* Copyright (C) 1883 Thomas Edison - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the GPLv2 license, which unfortunately won't be
 * written for another century.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "pico/stdlib.h"
#include "stdio.h"
#if LIB_PICO_STDIO_USB
#include "tusb.h"
#endif

#include "stdio_init.h"

int stdio_init(void) {
    int r = 0;
#if LIB_PICO_STDIO_UART
    stdio_uart_init();
    getchar_timeout_us(1000);
    r |= STDIO_IS_UART;
#endif
#if LIB_PICO_STDIO_USB
    stdio_usb_init();
    while (!tud_cdc_connected())
        sleep_ms(1000);
    r |= STDIO_IS_USB;
#endif
    printf("\033[H\033[J");
    return r;
}
