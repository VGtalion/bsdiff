/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 2003-2005 Colin Percival
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#if 0
__FBSDID("$FreeBSD$");
#endif

#include <bzlib.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif
#define HEADER_SIZE 32

/* TYPE_MINIMUM and TYPE_MAXIMUM taken from coreutils */
#ifndef TYPE_MINIMUM
#define TYPE_MINIMUM(t) \
  ((t) ((t) 0 < (t) -1 ? (t) 0 : ~ TYPE_MAXIMUM (t)))
#endif
#ifndef TYPE_MAXIMUM
#define TYPE_MAXIMUM(t) \
  ((t) ((t) 0 < (t) -1 \
        ? (t) -1 \
        : ((((t) 1 << (sizeof (t) * CHAR_BIT - 2)) - 1) * 2 + 1)))
#endif

#ifndef OFF_MAX
#define OFF_MAX TYPE_MAXIMUM(off_t)
#endif

#ifndef OFF_MIN
#define OFF_MIN TYPE_MINIMUM(off_t)
#endif

static char *newfile;
static int dirfd = -1;

static void
exit_cleanup(void)
{

	if (dirfd != -1 && newfile != NULL)
		if (unlinkat(dirfd, newfile, 0))
			warn("unlinkat");
}

static inline off_t
add_off_t(off_t a, off_t b)
{
	off_t result;

#if __GNUC__ >= 5 || \
    (defined(__has_builtin) && __has_builtin(__builtin_add_overflow))
	if (__builtin_add_overflow(a, b, &result))
		errx(1, "Corrupt patch");
#else
	if ((b > 0 && a > OFF_MAX - b) || (b < 0 && a < OFF_MIN - b))
		errx(1, "Corrupt patch");
	result = a + b;
#endif
	return result;
}

static off_t offtin(u_char *buf)
{
	off_t y;

	y = buf[7] & 0x7F;
	y = y * 256; y += buf[6];
	y = y * 256; y += buf[5];
	y = y * 256; y += buf[4];
	y = y * 256; y += buf[3];
	y = y * 256; y += buf[2];
	y = y * 256; y += buf[1];
	y = y * 256; y += buf[0];

	if (buf[7] & 0x80)
		y = -y;

	return (y);
}

static void
usage(void)
{

	fprintf(stderr, "usage: bspatch oldfile newfile patchfile\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	FILE *f, *cpf, *dpf, *epf;
	BZFILE *cpfbz2, *dpfbz2, *epfbz2;
	char *directory, *namebuf;
	int cbz2err, dbz2err, ebz2err;
	int newfd, oldfd;
	off_t oldsize, newsize;
	off_t bzctrllen, bzdatalen;
	u_char header[HEADER_SIZE], buf[8];
	u_char *old, *new;
	off_t oldpos, newpos;
	off_t ctrl[3];
	off_t i, lenread, offset;

	if (argc != 4)
		usage();

	/* Open patch file */
	if ((f = fopen(argv[3], "rb")) == NULL)
		err(1, "fopen(%s)", argv[3]);
	/* Open patch file for control block */
	if ((cpf = fopen(argv[3], "rb")) == NULL)
		err(1, "fopen(%s)", argv[3]);
	/* open patch file for diff block */
	if ((dpf = fopen(argv[3], "rb")) == NULL)
		err(1, "fopen(%s)", argv[3]);
	/* open patch file for extra block */
	if ((epf = fopen(argv[3], "rb")) == NULL)
		err(1, "fopen(%s)", argv[3]);
	/* open oldfile */
        oldfd = open(argv[1], O_RDONLY,0);
	if (oldfd < 0)
		err(1, "Open %s", argv[1]);
	/* open directory where we'll write newfile */
	if ((namebuf = strdup(argv[2])) == NULL ||
	    (directory = dirname(namebuf)) == NULL ||
	    (dirfd = open(directory, O_DIRECTORY)) < 0)
		err(1, "open %s", argv[2]);
	free(namebuf);
	if ((newfile = basename(argv[2])) == NULL)
		err(1, "basename");
	/* open newfile */
	newfd = openat(dirfd, newfile, O_RDWR|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
	if (newfd < 0)
		err(1, "open(%s)", argv[2]);

	atexit(exit_cleanup);

	/*
	File format:
		0	8	"BSDIFF40"
		8	8	X
		16	8	Y
		24	8	sizeof(newfile)
		32	X	bzip2(control block)
		32+X	Y	bzip2(diff block)
		32+X+Y	???	bzip2(extra block)
	with control block a set of triples (x,y,z) meaning "add x bytes
	from oldfile to x bytes from the diff block; copy y bytes from the
	extra block; seek forwards in oldfile by z bytes".
	*/

	/* Read header */
	if (fread(header, 1, HEADER_SIZE, f) < HEADER_SIZE) {
		if (feof(f))
			errx(1, "Corrupt patch");
		err(1, "fread(%s)", argv[3]);
	}

	/* Check for appropriate magic */
	if (memcmp(header, "BSDIFF40", 8) != 0)
		errx(1, "Corrupt patch");

	/* Read lengths from header */
	bzctrllen = offtin(header + 8);
	bzdatalen = offtin(header + 16);
	newsize = offtin(header + 24);
	if (bzctrllen < 0 || bzctrllen > OFF_MAX - HEADER_SIZE ||
	    bzdatalen < 0 || bzctrllen + HEADER_SIZE > OFF_MAX - bzdatalen ||
	    newsize < 0 || newsize > SSIZE_MAX)
		errx(1, "Corrupt patch");

	/* Close patch file and re-open it via libbzip2 at the right places */
	if (fclose(f))
		err(1, "fclose(%s)", argv[3]);
	offset = HEADER_SIZE;
	if (fseeko(cpf, offset, SEEK_SET))
		err(1, "fseeko(%s, %jd)", argv[3], (intmax_t)offset);
	if ((cpfbz2 = BZ2_bzReadOpen(&cbz2err, cpf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", cbz2err);
	offset = add_off_t(offset, bzctrllen);
	if (fseeko(dpf, offset, SEEK_SET))
		err(1, "fseeko(%s, %jd)", argv[3], (intmax_t)offset);
	if ((dpfbz2 = BZ2_bzReadOpen(&dbz2err, dpf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", dbz2err);
	offset = add_off_t(offset, bzdatalen);
	if (fseeko(epf, offset, SEEK_SET))
		err(1, "fseeko(%s, %jd)", argv[3], (intmax_t)offset);
	if ((epfbz2 = BZ2_bzReadOpen(&ebz2err, epf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", ebz2err);

	oldsize = lseek(oldfd, 0, SEEK_END);
	if (oldsize < 0)
		err(1, "seek %s", argv[1]);

	old = mmap(NULL, oldsize, PROT_READ, MAP_SHARED | MAP_POPULATE, oldfd, 0);
	if (old == MAP_FAILED)
		err(1, "mmap() %s", argv[1]);
	if(close(oldfd)==-1)
		err(1, "close() %s", argv[1]);

	if(newsize > 0){
		if(lseek(newfd, newsize-1, SEEK_SET) < 0)
			err(1, "seek %s", argv[2]);
		if(write(newfd, "", 1) != 1)
			err(1, "write %s", argv[2]);
	}
	new = mmap(NULL, newsize, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_POPULATE, newfd, 0);
	if (new == MAP_FAILED)
		err(1, "mmap %s", argv[2]);
	close(newfd);

	oldpos = 0;
	newpos = 0;
	while (newpos < newsize) {
		/* Read control data */
		for (i = 0; i <= 2; i++) {
			lenread = BZ2_bzRead(&cbz2err, cpfbz2, buf, 8);
			if ((lenread < 8) || ((cbz2err != BZ_OK) &&
			    (cbz2err != BZ_STREAM_END)))
				errx(1, "Corrupt patch");
			ctrl[i] = offtin(buf);
		}

		/* Sanity-check */
		if (ctrl[0] < 0 || ctrl[0] > INT_MAX ||
		    ctrl[1] < 0 || ctrl[1] > INT_MAX)
			errx(1, "Corrupt patch");

		/* Sanity-check */
		if (add_off_t(newpos, ctrl[0]) > newsize)
			errx(1, "Corrupt patch");

		/* Read diff string */
		lenread = BZ2_bzRead(&dbz2err, dpfbz2, new + newpos, ctrl[0]);
		if ((lenread < ctrl[0]) ||
		    ((dbz2err != BZ_OK) && (dbz2err != BZ_STREAM_END)))
			errx(1, "Corrupt patch");

		/* Add old data to diff string */
		for (i = 0; i < ctrl[0]; i++)
			if (add_off_t(oldpos, i) < oldsize)
				new[newpos + i] += old[oldpos + i];

		/* Adjust pointers */
		newpos = add_off_t(newpos, ctrl[0]);
		oldpos = add_off_t(oldpos, ctrl[0]);

		/* Sanity-check */
		if (add_off_t(newpos, ctrl[1]) > newsize)
			errx(1, "Corrupt patch");

		/* Read extra string */
		lenread = BZ2_bzRead(&ebz2err, epfbz2, new + newpos, ctrl[1]);
		if ((lenread < ctrl[1]) ||
		    ((ebz2err != BZ_OK) && (ebz2err != BZ_STREAM_END)))
			errx(1, "Corrupt patch");

		/* Adjust pointers */
		newpos = add_off_t(newpos, ctrl[1]);
		oldpos = add_off_t(oldpos, ctrl[2]);
	}

	/* Clean up the bzip2 reads */
	BZ2_bzReadClose(&cbz2err, cpfbz2);
	BZ2_bzReadClose(&dbz2err, dpfbz2);
	BZ2_bzReadClose(&ebz2err, epfbz2);
	if (fclose(cpf) || fclose(dpf) || fclose(epf))
		err(1, "fclose(%s)", argv[3]);

	/* Disable atexit cleanup */
	newfile = NULL;

	munmap(new, newsize);
	munmap(old, oldsize);

	return (0);
}
