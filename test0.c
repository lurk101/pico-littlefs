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

#include "pico/stdio.h"

#include "pico_hal.h"

// application entry point
int main(void) {

    // initialize the pico SDK
    stdio_init_all();
    getchar_timeout_us(1000);  // swallow the spurious EOF character???
    printf("\033[H\033[J");    // try to clear the screen
    printf("format (N/y) ? "); // try to clear the screen
    char c = getchar();
    printf("\n");

    // increment the boot count with each invocation
    lfs_size_t boot_count;
    // variables used by the filesystem
    int file;
    // mount the filesystem
    if (pico_mount((c | ' ') == 'y') != LFS_ERR_OK) {
        printf("Error mounting FS\n");
        exit;
    }
    struct pico_fsstat_t stat;
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // read current count
    file = pico_open("boot_count", LFS_O_RDWR | LFS_O_CREAT);
    boot_count = 0;
    pico_read(file, &boot_count, sizeof(boot_count));
    boot_count += 1;
    pico_rewind(file);
    pico_write(file, &boot_count, sizeof(boot_count));
    pico_rewind(file);
	int pos = pico_lseek(file, 0, LFS_SEEK_END);
    // remember the storage is not updated until the file is closed successfully
    pico_close(file);
    // release any resources we were using
    pico_unmount();
    // print the boot count
    printf("boot_count: %d\n", (int)boot_count);
    printf("file size: %d\n", pos);
}
