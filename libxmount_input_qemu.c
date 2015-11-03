/*
 * libxmount_input_qemu.c
 *
 *  Created on: Nov 3, 2015
 *      Author: thomas
 */

#include <stdint.h>
#include <xmount/libxmount_input/libxmount_input.h>

#include "block/block.h"
#include "qapi/error.h"

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
};

typedef struct {
    uint8_t debug;

    BlockDriverState *bds;
} XmountQemuHandle;


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

    bdrv_init();
    handle->bds = bdrv_new();

    *pp_handle = handle;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_destroy_handle(void **pp_handle) {
    bdrv_close_all();
    free(*pp_handle);
    *pp_handle = 0;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_open(void *p_handle,
                     const char **pp_filename_arr,
                     uint64_t filename_arr_len) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;

    if (filename_arr_len != 1) {
        return XMOUNT_QEMU_SINGLE_FILE;
    }

    int flags = BDRV_O_RDWR;
    Error *error = 0;
    if (bdrv_open(&handle->bds, pp_filename_arr[0], 0, 0, flags, &error)) {
        printf("Error opening Qemu block driver: %s\n", error_get_pretty(error));
        return XMOUNT_QEMU_CANNOT_OPEN;
    }

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_close(void *p_handle) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;

    bdrv_close(handle->bds);

    return XMOUNT_QEMU_OK;
}

int xmount_qemu_size(void *p_handle,
                     uint64_t *p_size) {
    XmountQemuHandle *handle = (XmountQemuHandle *)p_handle;

    *p_size = bdrv_getlength(handle->bds);
    LIBXMOUNT_LOG_DEBUG(handle->debug,
                        "Returned size of block driver: %" PRIu64 "\n", *p_size);
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_read(void *p_handle,
                     char *p_buf,
                     off_t offset,
                     size_t count,
                     size_t *p_read,
                     int *p_errno) {
    return 1;
}

int xmount_qemu_write(void *p_handle,
                      const char *p_buf,
                      off_t offset,
                      size_t count,
                      size_t *p_written,
                      int *p_errno) {
    return 1;
}

int xmount_qemu_options_help(const char **pp_help) {
    *pp_help = "";
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_options_parse(void *p_handle,
                              uint32_t options_count,
                              const pts_LibXmountOptions *pp_options,
                              const char **pp_error) {
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_get_infofile_content(void *p_handle,
                                     const char **pp_info_buf) {
    *pp_info_buf = "";
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
    return "qcow2\0";
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
