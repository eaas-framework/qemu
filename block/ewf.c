/*
 * Block driver for EWF files
 *
 * Copyright (c) 2006 Thomas Liebetraut, based on work by Oleg Stobbe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "block/block_int.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qstring.h"

#include <libewf.h>

//#define DEBUG_EWF

#ifdef DEBUG_EWF
#define DPRINTF(fmt, ...) do { printf("%s:%d: " fmt, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif


typedef struct BDRVEwfState {
} BDRVEwfState;


static int ewf_probe(const uint8_t *buf, int buf_size, const char *filename);
static int ewf_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp);
static void ewf_close(BlockDriverState *bs);
static void bdrv_ewf_init(void);


static int ewf_probe(const uint8_t *buf, int buf_size, const char *filename)
{
	return -1;
}

static int ewf_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    return -1;
}

static void ewf_close(BlockDriverState *bs)
{
}

static BlockDriver bdrv_ewf = {
	.format_name = "ewf",
 	.instance_size = sizeof(BDRVEwfState),
	.bdrv_probe = ewf_probe,
	.bdrv_open = ewf_open,
	.bdrv_close = ewf_close,
};

static void bdrv_ewf_init(void)
{
    /*
     * Register all the drivers.  Note that order is important, the driver
     * registered last will get probed first.
     */
    bdrv_register(&bdrv_ewf);
}

block_init(bdrv_ewf_init);
