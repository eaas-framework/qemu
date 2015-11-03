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

    bdrv_close(&handle->bds);

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
    p_functions->GetErrorMessage = xmount_qemu_get_error_message;
}
