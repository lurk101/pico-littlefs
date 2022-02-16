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
#include "pico/stdlib.h"

#include "pico_hal.h"
#include "stdinit.h"

/* We'll create 32 files with randon names, verify them, rename them, reverify,
 * and delete them.
 */

void dump_dir(void) {
	// display each directory entry name
	printf("File list\n");
    int dir = pico_dir_open("/");
    if (dir < 0)
        return;
    struct lfs_info info;
    while (pico_dir_read(dir, &info) > 0)
        printf("%s\n", info.name);
    pico_dir_close(dir);
	printf("End of list\n");
}

int main() {
	const char* fn_templ1 = "1%u.tst";
	const char* fn_templ2 = "2%u.tst";

	// Initialize console
    stdio_init();
	// Seed the random number generator
	printf("Hit any key\n");
	getchar();
	unsigned seed = time_us_32();
	srand(seed);
	// Mount the file stsrem
    if (pico_mount(false) < 0) {
        printf("Mount failed\n");
        exit(-1);
    }
    dump_dir();
	// File handle and file name
    int file;
    char fn[32], fn2[32];
	// Create 32 file
    printf("Creating 32 files\n");
    for (int i = 0; i < 32; i++) {
		// Get numeric part of file name
		unsigned n = rand();
		// Create file name string
        sprintf(fn, fn_templ1, n);
		// Create the file
        file = pico_open(fn, LFS_O_WRONLY | LFS_O_CREAT);
        if ((int)file < 0) {
            printf("open fails\n");
            goto fail;
        }
        // Write the file name to the file
        if ((strlen(fn) + 1) != (uint32_t)pico_write(file, fn, strlen(fn) + 1)) {
            printf("write fails\n");
            goto fail;
        }
		// flush and close the file
        pico_close(file);
    }
	dump_dir();
    // Unmount & remount
    pico_unmount();
    pico_mount(false);
    // Display file system sizes
    struct pico_fsstat_t stat;
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    printf("Renaming 32 files\n");
	// Reset the random sequence
	srand(seed);
    for (int i = 0; i < 32; i++) {
		// Get numeric part of file name
		unsigned n = rand();
		unsigned n2 = n ^ 0xffff;
        sprintf(fn, fn_templ1, n);
        sprintf(fn2, fn_templ2, n2);
		// rename
        if (pico_rename(fn, fn2) < 0) {
            printf("rename fails\n");
            goto fail;
        }
    }
	dump_dir();
	// Display file system sizes
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    printf("Verifying then removing 32 files\n");
    char buf[32];
	// Reset the random sequence
	srand(seed);
    for (int i = 0; i < 32; i++) {
		// Get numeric part of file name
		unsigned n = rand();
		unsigned n2 = n ^ 0xffff;
        sprintf(fn, fn_templ1, n);
        sprintf(fn2, fn_templ2, n2);
        // verify the file's content
        file = pico_open(fn2, LFS_O_RDONLY);
        if (file < 0) {
            printf("open fails\n");
            goto fail;
        }
        lfs_size_t len = pico_read(file, buf, sizeof(buf));
        if (strcmp(fn, buf) != 0) {
            printf("read fails\n");
            goto fail;
        }
        pico_close(file);
		// Delete the file
        if (pico_remove(fn2) < 0) {
            printf("remove fails\n");
            goto fail;
        }
    }
	dump_dir();
	// Display file system sizes
    pico_fsstat(&stat);
    printf("FS: blocks %d, block size %d, used %d\n", (int)stat.block_count, (int)stat.block_size,
           (int)stat.blocks_used);
    // Release any resources we were using
    pico_unmount();
    printf("Pass\n");
    return 0;
fail:
    pico_unmount();
    printf("Fail\n");
    return -1;
}
