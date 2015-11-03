/*
 * libxmount_input_qemu.c
 *
 *  Created on: Nov 3, 2015
 *      Author: thomas
 */

#include <stdint.h>
#include <xmount/libxmount_input/libxmount_input.h>


enum XmountQemuErrors {
    XMOUNT_QEMU_OK = 0,
    XMOUNT_QEMU_BAD_ALLOC,
};

typedef struct {
    uint8_t debug;
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

    *pp_handle = handle;
    return XMOUNT_QEMU_OK;
}

int xmount_qemu_destroy_handle(void **pp_handle) {
    free(*pp_handle);
    *pp_handle = 0;
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
    p_functions->GetErrorMessage = xmount_qemu_get_error_message;
}
