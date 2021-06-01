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

#include "hal.h"

const char* fn_template = "file%d.tst";
const uint32_t n_files = 128;

// application entry point
int main(void) {

    // variables used by the filesystem
    lfs_file_t file;
    lfs_t pico_lfs;

    // initialize the pico SDK
    stdio_init_all();
    printf("\033[H\033[J"); // try to clear the screen

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

    uint32_t i;
    char fn[32];

    printf("Creating %d files\n", (int)n_files);
    for (i = 0; i < n_files; i++) {
        sprintf(fn, fn_template, i);
        if (0 > lfs_file_open(&pico_lfs, &file, fn, LFS_O_RDWR | LFS_O_CREAT)) {
            printf("open fails\n");
            return -1;
        }
        // write the file name
        if ((strlen(fn) + 1) != (uint32_t)lfs_file_write(&pico_lfs, &file, fn, strlen(fn) + 1)) {
            printf("write fails\n");
            return -1;
        }
        lfs_file_close(&pico_lfs, &file);
    }

    printf("Verifying then removing %d files\n", (int)n_files);
    char buf[32];
    for (i = 0; i < n_files; i++) {
        // scramble the file name order
        sprintf(fn, fn_template, i ^ (0xaa & (n_files - 1)));
        // verify the file's content
        if (0 > lfs_file_open(&pico_lfs, &file, fn, LFS_O_RDONLY)) {
            printf("open fails\n");
            return -1;
        }
        lfs_size_t len = lfs_file_read(&pico_lfs, &file, buf, sizeof(buf));
        if ((len != strlen(fn) + 1) || (strcmp(fn, buf) != 0)) {
            printf("read fails\n");
            return -1;
        }
        lfs_file_close(&pico_lfs, &file);
        if (0 > lfs_remove(&pico_lfs, fn)) {
            printf("remove fails\n");
            return -1;
        }
    }
    // release any resources we were using
    lfs_unmount(&pico_lfs);

    printf("pass\n");
}
