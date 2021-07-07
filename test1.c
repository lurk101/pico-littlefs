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

#include "pico_hal.h"

const char* fn_templ1 = "old%d.tst";
const char* fn_templ2 = "new%d.tst";
const uint32_t n_files = 32;

// application entry point
int main(void) {

    // variables used by the filesystem
    int file;

    // initialize the pico SDK
    stdio_init_all();
    printf("\033[H\033[J"); // try to clear the screen

    // mount the filesystem
    posix_mount();

    uint32_t i;
    char fn[32], fn2[32];

    printf("Creating %d files\n", (int)n_files);
    hal_start();
    for (i = 0; i < n_files; i++) {
        sprintf(fn, fn_templ1, i);
        file = posix_open(fn, LFS_O_RDWR | LFS_O_CREAT);
        if ((int)file < 0) {
            printf("open fails\n");
            return -1;
        }
        // write the file name
        if ((strlen(fn) + 1) != (uint32_t)posix_write(file, fn, strlen(fn) + 1)) {
            printf("write fails\n");
            return -1;
        }
        posix_close(file);
    }
    printf("elapsed %f seconds\n", hal_elapsed());

    printf("Renaming %d files\n", (int)n_files);
    hal_start();
    for (i = 0; i < n_files; i++) {
        uint32_t j = i ^ (0x55 & (n_files - 1));
        sprintf(fn, fn_templ1, j);
        sprintf(fn2, fn_templ2, j);
        if (posix_rename(fn, fn2) < 0) {
            printf("rename fails\n");
            return -1;
        }
    }
    printf("elapsed %f seconds\n", hal_elapsed());

    printf("Verifying then removing %d files\n", (int)n_files);
    char buf[32];
    hal_start();
    for (i = 0; i < n_files; i++) {
        // scramble the file name order
        uint32_t j = i ^ (0xaa & (n_files - 1));
        sprintf(fn, fn_templ1, j);
        sprintf(fn2, fn_templ2, j);
        // verify the file's content
        file = posix_open(fn2, LFS_O_RDONLY);
        if (file < 0) {
            printf("open fails\n");
            return -1;
        }
        lfs_size_t len = posix_read(file, buf, sizeof(buf));
        if ((len != strlen(fn) + 1) || (strcmp(fn, buf) != 0)) {
            printf("read fails\n");
            return -1;
        }
        posix_close(file);
        if (posix_remove(fn2) < 0) {
            printf("remove fails\n");
            return -1;
        }
    }
    printf("elapsed %f seconds\n", hal_elapsed());
    // release any resources we were using
    posix_unmount();

    printf("pass\n");
}
