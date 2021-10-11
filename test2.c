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

#define FILE_SIZE (200 * 1024)
#define BUF_WRDS (1024 / sizeof(uint32_t))

static uint32_t buf[BUF_WRDS];

// application entry point
int main(void) {

    const char* fn = "big_file";

    // variables used by the filesystem
    int file;

    // initialize the pico SDK
    stdio_init_all();
    printf("\033[H\033[J"); // try to clear the screen

    // mount the filesystem
    pico_mount(false);

    struct pico_fsstat_t stat;
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);

    uint32_t i, n;

    printf("Creating %dK file\n", (int)(FILE_SIZE / 1024));
    hal_start();
    file = pico_open(fn, LFS_O_WRONLY | LFS_O_CREAT);
    if (file < 0) {
        printf("open fails\n");
        return -1;
    }
    n = FILE_SIZE;
    srand(12345);
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        for (i = 0; i < BUF_WRDS; i++)
            buf[i] = rand();
        lfs_size_t len = pico_write(file, buf, sizeof(buf));
        if (sizeof(buf) != (uint32_t)len) {
            printf("write fails at %d returned %d\n", (int)n, (int)len);
            break;
        }
    }
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    pico_close(file);
    if (n < FILE_SIZE) {
        pico_remove(fn);
        pico_unmount();
        return -1;
    }
    printf("elapsed %f seconds\n", hal_elapsed());

    printf("reading %dK file\n", (int)(FILE_SIZE / 1024));
    hal_start();
    file = pico_open(fn, LFS_O_RDONLY);
    if (file < 0) {
        printf("open fails\n");
        return -1;
    }
    n = FILE_SIZE;
    srand(12345);
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        lfs_size_t len = pico_read(file, buf, sizeof(buf));
        if (sizeof(buf) != (uint32_t)len) {
            printf("read fails at %d returned %d\n", (int)n, (int)len);
            break;
        }
        for (i = 0; i < BUF_WRDS; i++)
            if (buf[i] != (uint32_t)rand()) {
                printf("data mismatch at %d\n", (int)n);
                break;
            }
    }
    pico_close(file);
    printf("elapsed %f seconds\n", hal_elapsed());

    printf("removing file\n");
    if (pico_remove(fn) < 0) {
        printf("remove fails\n");
        return -1;
    }
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // release any resources we were using
    pico_unmount();
    if (n < FILE_SIZE) {
        return -1;
    }

    printf("pass\n");
}
