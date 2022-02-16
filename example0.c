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
#include "stdinit.h"

/* mount counter.
 * In this example we'll check increment the mount count file content.
 */

int main() {
	// Initialize the console
    stdio_init();
	// Optionally format, the mount the file system
    printf("format (N/y) ? "); // try to clear the screen
    char c = getchar();
    printf("\n");
    if (pico_mount((c | ' ') == 'y') != LFS_ERR_OK) {
        printf("Error mounting FS\n");
        exit(-1);
    }
	// Show file system sizes
    struct pico_fsstat_t stat;
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // increment the boot count with each invocation
    lfs_size_t boot_count;
	// Open (create if doesn't exist) the boot count file
    int file = pico_open("boot_count", LFS_O_RDWR | LFS_O_CREAT);
    boot_count = 0;
	// Read previous boot count. If file was just created read will return 0 bytes
    pico_read(file, &boot_count, sizeof(boot_count));
	// Increment the count
    boot_count += 1;
	// Write it back after seeking to start of file
    pico_rewind(file);
    pico_write(file, &boot_count, sizeof(boot_count));
	// save the file size
	int pos = pico_lseek(file, 0, LFS_SEEK_CUR);
	// Close the file, making sure all buffered data is flushed
    pico_close(file);
	// Unmount the file system, freeing memory
    pico_unmount();
	// Report
    printf("Boot count: %d\n", (int)boot_count);
    printf("File size (should be 4) : %d\n", pos);
}
