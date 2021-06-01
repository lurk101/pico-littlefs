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

#include "lfs.h"

#include "pico_hal.h"

// 256K of space for file system at top of pico flash
#define FS_SIZE (PICO_FLASH_SIZE_BYTES / 8)

#define FILE_SIZE (200 * 1024)
#define BUF_WRDS (1024 / sizeof(uint32_t))

static uint32_t buf[BUF_WRDS];

// application entry point
int main(void) {

    const char* fn = "big_file";

    // variables used by the filesystem
    lfs_file_t file;

    // initialize the pico SDK
    stdio_init_all();
    printf("\033[H\033[J"); // try to clear the screen

    pico_fs_size(FS_SIZE);

    // mount the filesystem
    int err = lfs_mount(&pico_lfs, &pico_cfg);

    // reformat if we can't mount the filesystem
    // this should only happen on the first boot
    if (err) {
        printf("1st time formatting\n");
        lfs_format(&pico_lfs, &pico_cfg);
        lfs_mount(&pico_lfs, &pico_cfg);
    }
    printf("FS size: %dK\n", (int)(pico_cfg.block_count * pico_cfg.block_size / 1024));

    uint32_t i, n;

    printf("Creating %dK file\n", (int)(FILE_SIZE / 1024));
    uint32_t start = time_us_32();
    if (0 > lfs_file_open(&pico_lfs, &file, fn, LFS_O_WRONLY | LFS_O_CREAT)) {
        printf("open fails\n");
        return -1;
    }
    n = FILE_SIZE;
    srand(12345);
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        for (i = 0; i < BUF_WRDS; i++)
            buf[i] = rand();
        lfs_size_t len = lfs_file_write(&pico_lfs, &file, buf, sizeof(buf));
        if (sizeof(buf) != (uint32_t)len) {
            printf("write fails at %d returned %d\n", (int)n, (int)len);
            break;
        }
    }
    lfs_file_close(&pico_lfs, &file);
    if (n < FILE_SIZE) {
        lfs_remove(&pico_lfs, fn);
        lfs_unmount(&pico_lfs);
        return -1;
    }
    printf("elapsed %f seconds\n", (time_us_32() - start) / 1000000.0);

    printf("reading %dK file\n", (int)(FILE_SIZE / 1024));
    start = time_us_32();
    if (0 > lfs_file_open(&pico_lfs, &file, fn, LFS_O_RDONLY)) {
        printf("open fails\n");
        return -1;
    }
    n = FILE_SIZE;
    srand(12345);
    for (n = 0; n < FILE_SIZE; n += sizeof(buf)) {
        lfs_size_t len = lfs_file_read(&pico_lfs, &file, buf, sizeof(buf));
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
    lfs_file_close(&pico_lfs, &file);
    printf("elapsed %f seconds\n", (time_us_32() - start) / 1000000.0);

    printf("removing file\n");
    if (0 > lfs_remove(&pico_lfs, fn)) {
        printf("remove fails\n");
        return -1;
    }
    // release any resources we were using
    lfs_unmount(&pico_lfs);
    if (n < FILE_SIZE) {
        return -1;
    }

    printf("pass\n");
}
