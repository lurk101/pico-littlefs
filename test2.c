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

#include "hardware/flash.h"
#include "hardware/regs/addressmap.h"
#include "pico/stdio.h"
#include "pico/time.h"

#include "lfs.h"

// 256K of space for file system at top of pico flash
#define FS_SIZE (PICO_FLASH_SIZE_BYTES / 8)

// hal function prototypes
static int pico_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer,
                     lfs_size_t size);
static int pico_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off,
                     const void* buffer, lfs_size_t size);
static int pico_erase(const struct lfs_config* c, lfs_block_t block);
static int pico_sync(const struct lfs_config* c);

// configuration of the filesystem is provided by this struct
// for Pico: prog size = 256, block size = 4096, so cache is 8K
// minimum cache = block size, must be multiple
static const struct lfs_config cfg = {
    // block device operations
    .read = pico_read,
    .prog = pico_prog,
    .erase = pico_erase,
    .sync = pico_sync,
    // block device configuration
    .read_size = 1,
    .prog_size = FLASH_PAGE_SIZE,
    .block_size = FLASH_SECTOR_SIZE,
    .block_count = FS_SIZE / FLASH_SECTOR_SIZE,
    .cache_size = FLASH_SECTOR_SIZE,
    .lookahead_size = 16,
    .block_cycles = 500,
};

// Pico specific hardware abstraction functions

// file system offset in flash
static const uint32_t fs_base = PICO_FLASH_SIZE_BYTES - FS_SIZE;

static int pico_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer,
                     lfs_size_t size) {
    (void)c;
    // read flash via XIP mapped space
    uint8_t* p = (uint8_t*)(XIP_NOCACHE_NOALLOC_BASE + fs_base + (block * FLASH_SECTOR_SIZE) + off);
    memcpy(buffer, p, size);
    return 0;
}

static int pico_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off,
                     const void* buffer, lfs_size_t size) {
    (void)c;
    uint32_t p = (block * FLASH_SECTOR_SIZE) + off;
    // program with SDK
    flash_range_program(fs_base + p, buffer, size);
    return 0;
}

static int pico_erase(const struct lfs_config* c, lfs_block_t block) {
    (void)c;
    uint32_t off = block * FLASH_SECTOR_SIZE;
    // erase with SDK
    flash_range_erase(fs_base + off, FLASH_SECTOR_SIZE);
    return 0;
}

static int pico_sync(const struct lfs_config* c) {
    (void)c;
    // nothing to do!
    return 0;
}

static const uint32_t file_size = 100 * 1024;

static char buf1[1024], buf2[1024];

// application entry point
int main(void) {

    const char* fn = "big_file";

    // variables used by the filesystem
    lfs_t lfs;
    lfs_file_t file;

    // initialize the pico SDK
    stdio_init_all();
    printf("\033[H\033[J"); // try to clear the screen

    // mount the filesystem
    int err = lfs_mount(&lfs, &cfg);

    // reformat if we can't mount the filesystem
    // this should only happen on the first boot
    if (err) {
        printf("1st time formatting\n");
        lfs_format(&lfs, &cfg);
        lfs_mount(&lfs, &cfg);
    }
    printf("FS size: %dK\n", (int)(cfg.block_count * cfg.block_size / 1024));

    uint32_t n;

    for (n = 0; n < 1024; n += 2) {
        buf1[n] = 0x55;
        buf1[n + 1] = 0xaa;
    }
    printf("Creating %dK file\n", (int)(file_size / 1024));
    uint32_t start = time_us_32();
    if (0 > lfs_file_open(&lfs, &file, fn, LFS_O_WRONLY | LFS_O_CREAT)) {
        printf("open fails\n");
        return -1;
    }
    n = file_size;
    for (n = 0; n < file_size; n += sizeof(buf1)) {
        lfs_size_t len = lfs_file_write(&lfs, &file, buf1, sizeof(buf1));
        if (sizeof(buf1) != (uint32_t)len) {
            printf("write fails at %d returned %d\n", (int)n, (int)len);
            break;
        }
    }
    lfs_file_close(&lfs, &file);
    if (n < file_size) {
        lfs_remove(&lfs, fn);
        lfs_unmount(&lfs);
        return -1;
    }
    printf("elapsed %f seconds\n", (time_us_32() - start) / 1000000.0);

    printf("reading %dK file\n", (int)(file_size / 1024));
    start = time_us_32();
    if (0 > lfs_file_open(&lfs, &file, fn, LFS_O_RDONLY)) {
        printf("open fails\n");
        return -1;
    }
    n = file_size;
    for (n = 0; n < file_size; n += sizeof(buf1)) {
        lfs_size_t len = lfs_file_read(&lfs, &file, buf2, sizeof(buf1));
        if (sizeof(buf1) != (uint32_t)len) {
            printf("read fails at %d returned %d\n", (int)n, (int)len);
            break;
        }
        if (memcmp(buf1, buf2, sizeof(buf1)) != 0) {
            printf("data mismatch at %d\n", (int)n);
            break;
        }
    }
    lfs_file_close(&lfs, &file);
    printf("elapsed %f seconds\n", (time_us_32() - start) / 1000000.0);

    printf("removing file\n");
    if (0 > lfs_remove(&lfs, fn)) {
        printf("remove fails\n");
        return -1;
    }
    // release any resources we were using
    lfs_unmount(&lfs);
    if (n < file_size) {
        return -1;
    }

    printf("pass\n");
}
