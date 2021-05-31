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

// application entry point
int main(void) {

    // increment the boot count with each invocation

    lfs_size_t boot_count;

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
        // create the boot count file
        boot_count = 0;
        lfs_file_open(&lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT);
        lfs_file_write(&lfs, &file, &boot_count, sizeof(boot_count));
        lfs_file_close(&lfs, &file);
    }
    printf("FS size: %dK\n", (int)(cfg.block_count * cfg.block_size / 1024));
    // read current count
    lfs_file_open(&lfs, &file, "boot_count", LFS_O_RDWR);
    lfs_file_read(&lfs, &file, &boot_count, sizeof(boot_count));

    // update boot count
    boot_count += 1;
    lfs_file_rewind(&lfs, &file);
    lfs_file_write(&lfs, &file, &boot_count, sizeof(boot_count));

    // remember the storage is not updated until the file is closed successfully
    lfs_file_close(&lfs, &file);

    // release any resources we were using
    lfs_unmount(&lfs);

    // print the boot count
    printf("boot_count: %d\n", (int)boot_count);
}
