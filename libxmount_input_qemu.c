/*
 * libxmount_input_qemu.c
 *
 *  Created on: Nov 3, 2015
 *      Author: thomas
 */

#include <qemu/osdep.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <xmount/libxmount_input/libxmount_input.h>

#include "block/block.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"

int xmount_qemu_create_handle(void **pp_handle,
                              const char *p_format,
                              uint8_t debug);
int xmount_qemu_destroy_handle(void **pp_handle);
int xmount_qemu_open(void *p_handle,
                     const char **pp_filename_arr,
                     uint64_t filename_arr_len);
int xmount_qemu_close(void *p_handle);
int xmount_qemu_size(void *p_handle, uint64_t *p_size);
int xmount_qemu_read(void *p_handle,
                     char *p_buf,
                     off_t offset,
                     size_t count,
                     size_t *p_read,
                     int *p_errno);
int xmount_qemu_write(void *p_handle,
                      const char *p_buf,
                      off_t offset,
                      size_t count,
                      size_t *p_written,
                      int *p_errno);
int xmount_qemu_options_help(const char **pp_help);
int xmount_qemu_options_parse(void *p_handle,
                              uint32_t options_count,
                              const pts_LibXmountOptions *pp_options,
                              const char **pp_error);
int xmount_qemu_get_infofile_content(void *p_handle,
                                     const char **pp_info_buf);
const char *xmount_qemu_get_error_message(int err_num);
int xmount_qemu_free_buffer(void *p_buf);


enum XmountQemuErrors {
    XMOUNT_QEMU_OK = 0,
    XMOUNT_QEMU_BAD_ALLOC,
    XMOUNT_QEMU_SINGLE_FILE,
    XMOUNT_QEMU_CANNOT_OPEN,
    XMOUNT_QEMU_CANNOT_READ_DATA,
    XMOUNT_QEMU_CANNOT_WRITE_DATA,
    XMOUNT_QEMU_READ_BEYOND_END_OF_IMAGE,
    XMOUNT_QEMU_WRITE_BEYOND_END_OF_IMAGE,
};

#define QEMU_OPTION_WRITABLE "qemuwritable"
#define QEMU_OPTION_WRITABLE_DEFAULT "false"
#define QEMU_OPTION_CACHE "bdrv_cache"
#define QEMU_OPTION_CACHE_DEFAULT "writethrough"

typedef struct {
    uint8_t debug;

    BlockDriverState *bds;
    char writable;
    char *cache;
    pid_t pid;
} XmountQemuHandle;

/*
 * Qemu's coroutine implementation looses its magic powers if the pid changes
 * changes and causes bdrv_* functions to hang forever. Unfortunately,
 * xmount/FUSE daemonizes and thus changes the pid.
 * This function should be called every time before the bdrv is accessed.
 * It re-creates a new Qemu AIO context (with the new pid) and assigns it
 * to the bdrv. The old context will be released by bdrv_set_aio_context().
 */
static void reinit_aio_context(XmountQemuHandle *handle) {
    pid_t pid = getpid();
    AioContext *aio_context = 0;

    if (handle->pid != pid) {
        aio_context = aio_context_new(0);
        bdrv_set_aio_context(handle->bds, aio_context);
        handle->pid = pid;
    }
}


int xmount_qemu_create_handle(void **pp_handle,
                              const char *p_format,
                              uint8_t debug) {
    XmountQemuHandle *handle = 0;

    handle = (XmountQemuHandle *)malloc(sizeof(XmountQemuHandle));
    if (!handle) {
        return XMOUNT_QEMU_BAD_ALLOC;
    }

    memset(handle, 0, sizeof(XmountQemuHandle));
    handle->debug = debug;
    handle->pid = getpid();

    Error *error = 0;
    if (qemu_init_main_loop(&error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }

    bdrv_init();
    handle->bds = bdrv_new();

    *pp_handle = handle;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_destroy_handle(void **pp_handle) {
    XmountQemuHandle *handle = (XmountQemuHandle *)*pp_handle;
    reinit_aio_context(handle);

    bdrv_close_all();
    if (handle->cache) {
        free(handle->cache);
        handle->cache = 0;
    }
    free(*pp_handle);
    *pp_handle = 0;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_open(void *p_handle,
                     const char **pp_filename_arr,
                     uint64_t filename_arr_len) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;
    reinit_aio_context(handle);
    bool writethrough;

    if (filename_arr_len != 1) {
        return XMOUNT_QEMU_SINGLE_FILE;
    }

    int flags = 0;
    if (handle->writable) {
        flags = BDRV_O_RDWR;
    }
    if (handle->cache && bdrv_parse_cache_mode(handle->cache, &flags, &writethrough)) {
        printf("Invalid cache mode `%s'", handle->cache);
        return XMOUNT_QEMU_CANNOT_OPEN;
    }
    Error *error = 0;
    if (bdrv_open(&handle->bds, pp_filename_arr[0], 0, 0, flags, &error)) {
        printf("Error opening Qemu block driver: %s\n", error_get_pretty(error));
        return XMOUNT_QEMU_CANNOT_OPEN;
    }

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_close(void *p_handle) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;
    reinit_aio_context(handle);

    bdrv_close_all();

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_size(void *p_handle,
                     uint64_t *p_size) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;
    reinit_aio_context(handle);

    if (p_size) {
        *p_size = bdrv_getlength(handle->bds);
        LIBXMOUNT_LOG_DEBUG(handle->debug,
                            "[QEMU] Returned size of block driver: %" PRIu64 "\n", *p_size);
    }
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_read(void *p_handle,
                     char *p_buf,
                     off_t offset,
                     size_t count,
                     size_t *p_read,
                     int *p_errno) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;
    reinit_aio_context(handle);

    if (!p_buf) {
        LIBXMOUNT_LOG_ERROR("[QEMU] p_buf argument to read function was 0.");
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_CANNOT_READ_DATA;
    }
    if (offset < 0) {
        LIBXMOUNT_LOG_ERROR("[QEMU] offset argument to read function is negative.");
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_CANNOT_READ_DATA;
    }
    if (offset + count > bdrv_getlength(handle->bds)) {
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_READ_BEYOND_END_OF_IMAGE;
    }


    LIBXMOUNT_LOG_DEBUG(handle->debug, "[QEMU] Reading %d bytes at offset %d\n", count, offset);
    if (p_read) {
        *p_read = 0;
    }

    int ret = bdrv_pread(handle->bds, offset, p_buf, count);
    if (ret < 0) {
        LIBXMOUNT_LOG_ERROR("[QEMU] bdrv_pread() returned with error code %d\n", ret)
        if (p_errno) {
            *p_errno = -ret;
        }
        return XMOUNT_QEMU_CANNOT_READ_DATA;
    }
    if (p_read) {
        *p_read = ret;
    }
    if (p_errno) {
        *p_errno = 0;
    }

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_write(void *p_handle,
                      const char *p_buf,
                      off_t offset,
                      size_t count,
                      size_t *p_written,
                      int *p_errno) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;
    reinit_aio_context(handle);

    if (!p_buf) {
        LIBXMOUNT_LOG_ERROR("[QEMU] p_buf argument to write function was 0.");
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_CANNOT_WRITE_DATA;
    }
    if (offset < 0) {
        LIBXMOUNT_LOG_ERROR("[QEMU] offset argument to write function is negative.");
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_CANNOT_WRITE_DATA;
    }
    if (offset + count > bdrv_getlength(handle->bds)) {
        if (p_errno) {
            *p_errno = EINVAL;
        }
        return XMOUNT_QEMU_WRITE_BEYOND_END_OF_IMAGE;
    }


    LIBXMOUNT_LOG_DEBUG(handle->debug, "[QEMU] Writing %d bytes at offset %d\n", count, offset);
    if (p_written) {
        *p_written = 0;
    }

    int ret = bdrv_pwrite(handle->bds, offset, p_buf, count);
    if (ret < 0) {
        LIBXMOUNT_LOG_ERROR("[QEMU] bdrv_pwrite() returned with error code %d\n", ret)
        if (p_errno) {
            *p_errno = -ret;
        }
        return XMOUNT_QEMU_CANNOT_WRITE_DATA;
    }
    if (p_written) {
        *p_written = ret;
    }
    if (p_errno) {
        *p_errno = 0;
    }

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_options_help(const char **pp_help) {
    char *help = 0;
    int l = asprintf(&help, "    %-12s : Specifies if write operations are to be allowed on the source image. Default: %s\n"
                            "    %-12s : Specifies the qemu bdrv caching mode. Default: %s\n",
                     QEMU_OPTION_WRITABLE, QEMU_OPTION_WRITABLE_DEFAULT,
                     QEMU_OPTION_CACHE, QEMU_OPTION_CACHE_DEFAULT);

    if (!help || l < 0) {
        return XMOUNT_QEMU_BAD_ALLOC;
    }

    *pp_help = help;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_options_parse(void *p_handle,
                              uint32_t options_count,
                              const pts_LibXmountOptions *pp_options,
                              const char **pp_error) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;

    for (uint32_t i = 0; i < options_count; ++i) {
        pts_LibXmountOptions option = pp_options[i];

        if (strcmp(option->p_key, QEMU_OPTION_WRITABLE) == 0) {
            char *value = (char *)calloc(strlen(option->p_value) + 1,
                                          sizeof(char));
            if (!value) {
                return XMOUNT_QEMU_BAD_ALLOC;
            }
            for (size_t l = 0; l < strlen(option->p_value); ++l) {
                value[l] = tolower(option->p_value[l]);
            }

            handle->writable = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            free(value);
        }
        if (strcmp(option->p_key, QEMU_OPTION_CACHE) == 0) {
            size_t value_length = strlen(option->p_value) + 1;
            handle->cache = (char *)calloc(value_length, sizeof(char));
            if (!handle->cache) {
                return XMOUNT_QEMU_BAD_ALLOC;
            }
            strncpy(handle->cache, option->p_value, value_length);
        }
    }

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_get_infofile_content(void *p_handle,
                                     const char **pp_info_buf) {
    // xmount required this to be a free-able copy
    char *info = 0;
    int l = asprintf(&info, "\n");
    if (!info || l < 0) {
        return XMOUNT_QEMU_BAD_ALLOC;
    }

    *pp_info_buf = info;
    return XMOUNT_QEMU_OK;
}



const char *xmount_qemu_get_error_message(int err_num) {
    switch(err_num) {
    case XMOUNT_QEMU_OK:
        return "No error.";
        break;
    case XMOUNT_QEMU_BAD_ALLOC:
        return "Unable to allocate memory.";
        break;
    case XMOUNT_QEMU_SINGLE_FILE:
        return "You have to pass exactly one file/url to the Qemu input module.";
        break;
    default:
        return "Unknown error.";
        break;
    }
}

int xmount_qemu_free_buffer(void *p_buf) {
    free(p_buf);
    return XMOUNT_QEMU_OK;
}

uint8_t LibXmount_Input_GetApiVersion() {
    return LIBXMOUNT_INPUT_API_VERSION;
}

const char* LibXmount_Input_GetSupportedFormats() {
    return "qemu\0";
}

void LibXmount_Input_GetFunctions(pts_LibXmountInputFunctions p_functions) {
    p_functions->CreateHandle = xmount_qemu_create_handle;
    p_functions->DestroyHandle = xmount_qemu_destroy_handle;
    p_functions->Open = xmount_qemu_open;
    p_functions->Close = xmount_qemu_close;
    p_functions->Size = xmount_qemu_size;
    p_functions->Read = xmount_qemu_read;
    p_functions->Write = xmount_qemu_write;
    p_functions->OptionsHelp = xmount_qemu_options_help;
    p_functions->OptionsParse = xmount_qemu_options_parse;
    p_functions->GetInfofileContent = xmount_qemu_get_infofile_content;
    p_functions->GetErrorMessage = xmount_qemu_get_error_message;
    p_functions->FreeBuffer = xmount_qemu_free_buffer;
}
