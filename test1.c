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

const char* fn_template = "file%d.tst";
const uint32_t n_files = 128;

// application entry point
int main(void) {

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

    uint32_t i;
    char fn[32];

    printf("Creating %d files\n", (int)n_files);
    for (i = 0; i < n_files; i++) {
        sprintf(fn, fn_template, i);
        if (0 > lfs_file_open(&lfs, &file, fn, LFS_O_RDWR | LFS_O_CREAT)) {
            printf("open fails\n");
            return -1;
        }
        // write the file name
        if ((strlen(fn) + 1) != (uint32_t)lfs_file_write(&lfs, &file, fn, strlen(fn) + 1)) {
            printf("write fails\n");
            return -1;
        }
        lfs_file_close(&lfs, &file);
    }

    printf("Verifying then removing %d files\n", (int)n_files);
    char buf[32];
    for (i = 0; i < n_files; i++) {
        // scramble the file name order
        sprintf(fn, fn_template, i ^ (0xaa & (n_files - 1)));
        // verify the file's content
        if (0 > lfs_file_open(&lfs, &file, fn, LFS_O_RDONLY)) {
            printf("open fails\n");
            return -1;
        }
        lfs_size_t len = lfs_file_read(&lfs, &file, buf, sizeof(buf));
        if ((len != strlen(fn) + 1) || (strcmp(fn, buf) != 0)) {
            printf("read fails\n");
            return -1;
        }
        lfs_file_close(&lfs, &file);
        if (0 > lfs_remove(&lfs, fn)) {
            printf("remove fails\n");
            return -1;
        }
    }
    // release any resources we were using
    lfs_unmount(&lfs);

    printf("pass\n");
}
