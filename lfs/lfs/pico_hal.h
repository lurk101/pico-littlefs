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

#ifndef _HAL_
#define _HAL_

#include "lfs.h"

// utility functions

void hal_start(void);
float hal_elapsed(void);

// posix emulation

extern int posix_errno;

struct posix_fsstat_t {
    lfs_size_t block_size;
    lfs_size_t block_count;
    lfs_size_t blocks_used;
};

// implemented
int posix_mount(bool format);
int posix_unmount(void);
int posix_remove(const char* path);
int posix_open(const char* path, int flags);
int posix_close(int file);
int posix_fsstat(struct posix_fsstat_t* stat);
int posix_rewind(int file);
int posix_rename(const char* oldpath, const char* newpath);
lfs_size_t posix_read(int file, void* buffer, lfs_size_t size);
lfs_size_t posix_write(int file, const void* buffer, lfs_size_t size);
lfs_soff_t posix_lseek(int file, lfs_soff_t off, int whence);
int posix_truncate(int file, lfs_off_t size);
lfs_soff_t posix_tell(int file);

// to do
int posix_stat(const char* path, struct lfs_info* info);
lfs_ssize_t posix_getattr(const char* path, uint8_t type, void* buffer, lfs_size_t size);
int posix_setattr(const char* path, uint8_t type, const void* buffer, lfs_size_t size);
int posix_removeattr(const char* path, uint8_t type);
int posix_opencfg(const char* path, int flags, const struct lfs_file_config* config);
int posix_sync(int file);
lfs_soff_t posix_size(int file);
int posix_mkdir(const char* path);
int posix_dir_open(lfs_dir_t* dir, const char* path);
int posix_dir_close(lfs_dir_t* dir);
int posix_dir_read(lfs_dir_t* dir, struct lfs_info* info);
int posix_dir_seek(lfs_dir_t* dir, lfs_off_t off);
lfs_soff_t posix_dir_tell(lfs_dir_t* dir);
int posix_dir_rewind(lfs_dir_t* dir);
int posix_fs_traverse(int (*cb)(void*, lfs_block_t), void* data);
int posix_migrate(void);

#endif // _HAL_
