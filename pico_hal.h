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

#ifndef _PICO_HAL_
#define _PICO_HAL_

#include "lfs.h"

extern struct lfs_config pico_cfg;
extern lfs_t pico_lfs;

void pico_fs_size(lfs_size_t size);

int pico_read(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, void* buffer,
              lfs_size_t size);

int pico_prog(const struct lfs_config* c, lfs_block_t block, lfs_off_t off, const void* buffer,
              lfs_size_t size);

int pico_erase(const struct lfs_config* c, lfs_block_t block);

int pico_sync(const struct lfs_config* c);

#endif // _PICO_HAL_
