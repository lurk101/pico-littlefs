/* Copyright (C) 1883 Thomas Edison - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the BSD 3 clause license, which unfortunately
 * won't be written for another century.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * A little flash file system for the Raspberry Pico
 *
 */

#include "hardware/regs/addressmap.h"
#include "pico/stdio.h"
#include "pico/stdlib.h"
#include "pico/time.h"

#include "pico_hal.h"
#include "stdinit.h"

#define FILE_SIZE (200 * 1024)
#define BUF_WRDS (1024 / sizeof(uint32_t))

static uint32_t buf[BUF_WRDS];

// application entry point
int main(void) {
    // Initialize the console
    stdio_init();
    // Set the RNG seed
    printf("Hit any key\n");
    getchar();
    unsigned seed = time_us_32();
    srand(seed);
    // Mount the file system
    pico_mount(false);
    // Display file system sizes
    struct pico_fsstat_t stat;
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // Create a big file
    const char* fn = "big_file";
    int file = -1;
    uint32_t i, n;
    printf("Creating %dK file\n", (int)(FILE_SIZE / 1024));
    file = pico_open(fn, LFS_O_WRONLY | LFS_O_CREAT);
    int err = 0;
    if (file < 0) {
        printf("open fails\n");
        goto fail;
    }
    n = FILE_SIZE;
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        for (i = 0; i < BUF_WRDS; i++)
            buf[i] = rand();
        lfs_size_t len = pico_write(file, buf, sizeof(buf));
        if (sizeof(buf) != (uint32_t)len) {
            printf("write fails at %d returned %d\n", (int)n, (int)len);
            goto fail;
        }
    }
    pico_close(file);
    // Display file system sizes
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // Read back and verify the contensts
    printf("reading %dK file\n", (int)(FILE_SIZE / 1024));
    file = pico_open(fn, LFS_O_RDONLY);
    if (file < 0) {
        printf("open fails\n");
        goto fail;
    }
    n = FILE_SIZE;
    srand(seed);
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        lfs_size_t len = pico_read(file, buf, sizeof(buf));
        if (sizeof(buf) != (uint32_t)len) {
            printf("read fails at %d returned %d\n", (int)n, (int)len);
            goto fail;
        }
        for (i = 0; i < BUF_WRDS; i++)
            if (buf[i] != (uint32_t)rand()) {
                printf("data mismatch at %d\n", (int)n);
                goto fail;
            }
    }
    pico_close(file);
    // Delete the file
    printf("removing file\n");
    if (pico_remove(fn) < 0) {
        printf("remove fails\n");
        goto fail;
    }
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // release any resources we were using
    pico_unmount();
    printf("Pass\n");
    return 0;
fail:
    if (file >= 0)
        pico_close(file);
    pico_unmount();
    printf("Fail\n");
    return -1;
}
