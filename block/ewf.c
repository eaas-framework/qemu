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
#include <libbfio.h>

//#define DEBUG_EWF

#ifdef DEBUG_EWF
#define DPRINTF(fmt, ...) do { printf("%s:%d: " fmt, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif

typedef struct qemu_libbfio_io_handle {
    BlockDriverState *file;
    off64_t offset;
    bool opened;
} qemu_libbfio_io_handle;

typedef struct BDRVEwfState {
} BDRVEwfState;


int qemu_libbfio_io_handle_initialize(qemu_libbfio_io_handle **io_handle,
                                      libbfio_error_t **errp);
int qemu_libbfio_io_handle_clone(qemu_libbfio_io_handle **destination_io_handle,
                                 qemu_libbfio_io_handle *source_io_handle,
                                 libbfio_error_t **error);
int qemu_libbfio_io_handle_free(qemu_libbfio_io_handle **io_handle,
                                libbfio_error_t **error);
int qemu_libbfio_io_handle_set_file(qemu_libbfio_io_handle *io_handle,
                                    BlockDriverState *file,
                                    libbfio_error_t **error);
int qemu_libbfio_open(qemu_libbfio_io_handle *io_handle, int access_flags,
                      libbfio_error_t **error);
int qemu_libbfio_close(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error);
ssize_t qemu_libbfio_read(qemu_libbfio_io_handle *io_handle, uint8_t *buffer, size_t size,
                          libbfio_error_t **error);
ssize_t qemu_libbfio_write(qemu_libbfio_io_handle *io_handle, const uint8_t *buffer,
                           size_t size, libbfio_error_t **error);
off64_t qemu_libbfio_seek_offset(qemu_libbfio_io_handle *io_handle, off64_t offset,
                                 int whence, libbfio_error_t **error);
int qemu_libbfio_exists(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error);
int qemu_libbfio_is_open(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error);
int qemu_libbfio_get_size(qemu_libbfio_io_handle *io_handle, size64_t *size,
                          libbfio_error_t **error);

static int ewf_probe(const uint8_t *buf, int buf_size, const char *filename);
static int ewf_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp);
static void ewf_close(BlockDriverState *bs);
static void bdrv_ewf_init(void);


int qemu_libbfio_io_handle_initialize(qemu_libbfio_io_handle **io_handle,
                                      libbfio_error_t **errp) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }

    if (*io_handle) {
        DPRINTF("invalid qemu IO handle value already set.\n");
        return -1;
    }

    *io_handle = g_malloc0(sizeof(qemu_libbfio_io_handle));
    return 1;
}

int qemu_libbfio_io_handle_clone(qemu_libbfio_io_handle **destination_io_handle,
                                 qemu_libbfio_io_handle *source_io_handle,
                                 libbfio_error_t **error) {
    if (!destination_io_handle) {
        DPRINTF("invalid destination qemu IO handle.\n");
        return -1;
    }
    if (!*destination_io_handle) {
        DPRINTF("destination qemu IO handle already set.");
        return -1;
    }
    if (source_io_handle == 0) {
        *destination_io_handle = 0;
        return -1;
    }

    if (qemu_libbfio_io_handle_initialize(destination_io_handle, error) != 1) {
        DPRINTF("unable to create qemu IO handle.");
        return -1;
    }

    memmove(*destination_io_handle, source_io_handle,
            sizeof(qemu_libbfio_io_handle));

    return 1;
}

int qemu_libbfio_io_handle_free(qemu_libbfio_io_handle **io_handle,
                                libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    g_free(*io_handle);
    *io_handle = 0;

    return 1;
}

int qemu_libbfio_io_handle_set_file(qemu_libbfio_io_handle *io_handle,
                                    BlockDriverState *file,
                                    libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }

    io_handle->file = file;

    return 1;
}

int qemu_libbfio_open(qemu_libbfio_io_handle *io_handle, int access_flags,
                      libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    // nothing else to do here, the bds is not managed by us
    io_handle->opened = 1;
    return 1;
}

int qemu_libbfio_close(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    // nothing else to do here, the bds is not managed by us
    io_handle->opened = 0;
    return 1;
}

ssize_t qemu_libbfio_read(qemu_libbfio_io_handle *io_handle, uint8_t *buffer, size_t size,
                          libbfio_error_t **error) {
    int ret;

    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    ret = bdrv_pread(io_handle->file, io_handle->offset, buffer, size);

    if (ret < 0) {
        DPRINTF("could not read from qemu bds: %d\n", ret);
        return -1;
    }
    io_handle->offset += ret;
    return ret;
}

ssize_t qemu_libbfio_write(qemu_libbfio_io_handle *io_handle, const uint8_t *buffer,
                           size_t size, libbfio_error_t **error) {
    int ret;

    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    ret = bdrv_pwrite(io_handle->file, io_handle->offset, buffer, size);

    if (ret < 0) {
        DPRINTF("could not write to qemu bds: %d\n", ret);
        return -1;
    }
    io_handle->offset += ret;
    return ret;
}

off64_t qemu_libbfio_seek_offset(qemu_libbfio_io_handle *io_handle, off64_t offset,
                                 int whence, libbfio_error_t **error) {
    int64_t filesize = bdrv_getlength(io_handle->file);
    off64_t new_offset = 0;

    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    if (filesize < 0) {
        DPRINTF("could not determine qemu bds size: %"PRId64".\n", filesize);
        return -1;
    }

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = io_handle->offset + offset;
            break;
        case SEEK_END:
            new_offset = filesize - offset;
            break;
        default:
            break;
    }

    if (new_offset < 0 || new_offset > filesize) {
        DPRINTF("invalid seek offset %"PRId64".\n", new_offset);
        return -1;
    }
    io_handle->offset = new_offset;
    return io_handle->offset;
}

int qemu_libbfio_exists(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }

    // we handle a non-existing bdrv as ENOENT
    if (!io_handle->file) {
        return 0;
    }
    return 1;
}

int qemu_libbfio_is_open(qemu_libbfio_io_handle *io_handle, libbfio_error_t **error) {
    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        return 0;
    }

    return io_handle->opened;
}

int qemu_libbfio_get_size(qemu_libbfio_io_handle *io_handle, size64_t *size,
                          libbfio_error_t **error) {
    int64_t ret;

    if (!io_handle) {
        DPRINTF("invalid qemu IO handle.\n");
        return -1;
    }
    if (!io_handle->file) {
        DPRINTF("invalid qemu bdrv state.\n");
        return -1;
    }

    ret = bdrv_getlength(io_handle->file);
    if (ret < 0) {
        DPRINTF("could not determine bdrv length.\n");
        *size = 0;
        return -1;
    }

    *size = ret;
    return 1;
}


static int ewf_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    // buf contains the first buf_size bytes of the file.
    // we use the first few bytes to look for a EWF header as described
    // in the EWF and EWF 2.0 file format specifications

    // we need at least the first 8 bytes of a file
    if (!buf || buf_size < 8) {
        return 0;
    }

    // EWF (1.x):
    if (memcmp("EVF\x09\x0d\x0a\xff\x00", buf, 8) == 0) {
        return 100;
    }
    // don't check for LVF header (logical file evidence) as only full disk
    // images make sense for Qemu.

    // EWF 2.0
    if (memcmp("EVF2\x0d\x0a\x81\x00", buf, 8) == 0) {
        return 100;
    }
    // don't check for LVF2 header (logical file evidence) as only full disk
    // images make sense for Qemu.

    return 0;
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
