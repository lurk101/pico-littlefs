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

#include "lfs.h"

#include "pico_hal.h"

// 256K of space for file system at top of pico flash
#define FS_SIZE (PICO_FLASH_SIZE_BYTES / 8)

// application entry point
int main(void) {

    // increment the boot count with each invocation

    lfs_size_t boot_count;

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
        // create the boot count file
        boot_count = 0;
        lfs_file_open(&pico_lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT);
        lfs_file_write(&pico_lfs, &file, &boot_count, sizeof(boot_count));
        lfs_file_close(&pico_lfs, &file);
    }
    printf("FS size: %dK\n", (int)(pico_cfg.block_count * pico_cfg.block_size / 1024));
    // read current count
    lfs_file_open(&pico_lfs, &file, "boot_count", LFS_O_RDWR);
    lfs_file_read(&pico_lfs, &file, &boot_count, sizeof(boot_count));

    // update boot count
    boot_count += 1;
    lfs_file_rewind(&pico_lfs, &file);
    lfs_file_write(&pico_lfs, &file, &boot_count, sizeof(boot_count));

    // remember the storage is not updated until the file is closed successfully
    lfs_file_close(&pico_lfs, &file);

    // release any resources we were using
    lfs_unmount(&pico_lfs);

    // print the boot count
    printf("boot_count: %d\n", (int)boot_count);
}
