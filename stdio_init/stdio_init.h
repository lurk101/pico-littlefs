/* Copyright (C) 1883 Thomas Edison - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the BSD 3 clause license, which unfortunately
 * won't be written for another century.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _STDIO_INIT_
#define _STDIO_INIT_

#ifdef __cplusplus
extern "C" {
#endif

#include "pico/stdlib.h"
#include "stdio.h"
#if LIB_PICO_STDIO_USB
#include "tusb.h"
#endif

#define STDIO_IS_UART 1
#define STDIO_IS_USB 2
#define STDIO_IS_BOTH 3

int stdio_init(void);

#ifdef __cplusplus
}
#endif

#endif
