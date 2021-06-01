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

#include "hal.h"

#define FS_SIZE (256 * 1024)

static int pico_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer,
                     lfs_size_t size);

static int pico_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off,
                     const void* buffer, lfs_size_t size);

static int pico_erase(const struct lfs_config* c, lfs_block_t block);

static int pico_sync(const struct lfs_config* c);

// configuration of the filesystem is provided by this struct
// for Pico: prog size = 256, block size = 4096, so cache is 8K
// minimum cache = block size, must be multiple
struct lfs_config pico_cfg = {
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
    .lookahead_size = 32,
    .block_cycles = 500,
};

// Pico specific hardware abstraction functions

// file system offset in flash
#define FS_BASE (PICO_FLASH_SIZE_BYTES - FS_SIZE)

static int pico_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer,
                     lfs_size_t size) {
    (void)c;
    // read flash via XIP mapped space
    uint8_t* p =
        (uint8_t*)(XIP_NOCACHE_NOALLOC_BASE + FS_BASE + (block * pico_cfg.block_size) + off);
    memcpy(buffer, p, size);
    return LFS_ERR_OK;
}

static int pico_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off,
                     const void* buffer, lfs_size_t size) {
    (void)c;
    uint32_t p = (block * pico_cfg.block_size) + off;
    // program with SDK
    flash_range_program(FS_BASE + p, buffer, size);
    return LFS_ERR_OK;
}

static int pico_erase(const struct lfs_config* c, lfs_block_t block) {
    uint32_t off = block * pico_cfg.block_size;
    (void)c;
    // erase with SDK
    flash_range_erase(FS_BASE + off, pico_cfg.block_size);
    return LFS_ERR_OK;
}

static int pico_sync(const struct lfs_config* c) {
    (void)c;
    // nothing to do!
    return LFS_ERR_OK;
}
