/*
 * Copyright (c) 2023, Nordic Semiconductor ASA
 * Copyright (c) 2025, Siemens AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/retention/retention.h>
#include <zephyr/logging/log.h>
#include <bootutil/boot_record.h>
#include <bootutil/boot_status.h>
#include <../../bootutil/src/bootutil_priv.h>

#define SHARED_MEMORY_MIN_SIZE 8

LOG_MODULE_REGISTER(bootloader_info, CONFIG_RETENTION_LOG_LEVEL);

static bool shared_memory_init_done = false;
static uint16_t shared_data_size = SHARED_DATA_HEADER_SIZE;
static ssize_t shared_data_max_size = 0;
static const struct device *bootloader_info_dev =
                                    DEVICE_DT_GET(DT_CHOSEN(zephyr_bootloader_info));

BUILD_ASSERT(SHARED_MEMORY_MIN_SIZE < \
             DT_REG_SIZE_BY_IDX(DT_CHOSEN(zephyr_bootloader_info), 0), \
             "zephyr,bootloader-info area is too small for bootloader information struct");

int boot_add_data_to_shared_area(uint8_t        major_type,
                                 uint16_t       minor_type,
                                 size_t         size,
                                 const uint8_t *data)
{
    struct shared_data_tlv_header header = {
        .tlv_magic = SHARED_DATA_TLV_INFO_MAGIC,
        .tlv_tot_len = shared_data_size,
    };
    struct shared_data_tlv_entry tlv_entry = {0};
    uint16_t boot_data_size;
    uintptr_t tlv_end, offset;
    int rc;

    if (data == NULL) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Check whether first time to call this function. If does then initialise
     * shared data area.
     */
    if (!shared_memory_init_done) {
        retention_clear(bootloader_info_dev);
        shared_data_max_size = retention_size(bootloader_info_dev);
        shared_memory_init_done = true;
    }

    /* Check whether TLV entry is already added.
     * Get the boundaries of TLV section
     */
    tlv_end = shared_data_size;
    offset  = SHARED_DATA_HEADER_SIZE;

    /* Iterates over the TLV section looks for the same entry if found then
     * returns with error: SHARED_MEMORY_OVERWRITE
     */
    while (offset < tlv_end) {
        /* Create local copy to avoid unaligned access */
        rc = retention_read(bootloader_info_dev, offset, (void *)&tlv_entry,
                            SHARED_DATA_ENTRY_HEADER_SIZE);

        if (rc) {
            return SHARED_MEMORY_READ_ERROR;
        }

        if (GET_MAJOR(tlv_entry.tlv_type) == major_type &&
            GET_MINOR(tlv_entry.tlv_type) == minor_type) {
            return SHARED_MEMORY_OVERWRITE;
        }

        offset += SHARED_DATA_ENTRY_SIZE(tlv_entry.tlv_len);
    }

    /* Add TLV entry */
    tlv_entry.tlv_type = SET_TLV_TYPE(major_type, minor_type);
    tlv_entry.tlv_len  = size;

    if (!boot_u16_safe_add(&boot_data_size, shared_data_size,
                           SHARED_DATA_ENTRY_SIZE(size))) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Verify overflow of shared area */
    if (boot_data_size > shared_data_max_size) {
        return SHARED_MEMORY_OVERFLOW;
    }

    offset = shared_data_size;
    rc = retention_write(bootloader_info_dev, offset, (void*)&tlv_entry,
                         SHARED_DATA_ENTRY_HEADER_SIZE);
    if (rc) {
        LOG_ERR("Shared data TLV header write failed: %d", rc);
        return SHARED_MEMORY_WRITE_ERROR;
    }

    offset += SHARED_DATA_ENTRY_HEADER_SIZE;
    rc = retention_write(bootloader_info_dev, offset, data, size);

    if (rc) {
        LOG_ERR("Shared data TLV data write failed: %d", rc);
        return SHARED_MEMORY_WRITE_ERROR;
    }

    shared_data_size += SHARED_DATA_ENTRY_SIZE(size);
    header.tlv_tot_len = shared_data_size;

    rc = retention_write(bootloader_info_dev, 0, (void *)&header,
                         sizeof(header));

    if (rc) {
        return SHARED_MEMORY_WRITE_ERROR;
    }

    return SHARED_MEMORY_OK;
}

uint16_t
boot_load_shared_data(uint8_t major_type, uint16_t minor_type,
                      uint8_t *const buffer, size_t buffer_len)
{
    int rc;
    struct shared_data_tlv_header header;
    uintptr_t offset;
    struct shared_data_tlv_entry tlv_entry;

    /* Read header of shared data */
    rc = retention_read(bootloader_info_dev, 0,
                        (void *)&header, sizeof(header));
    if (rc) {
        LOG_ERR("Failed to read header of shared data: %d", rc);
        return UINT16_MAX;
    }

    /* Iterate over TLVs */
    offset = sizeof(header);
    while (offset < header.tlv_tot_len) {
        /* Create local copy to avoid unaligned access */
        rc = retention_read(bootloader_info_dev, offset,
                            (void *)&tlv_entry, sizeof(tlv_entry));
        if (rc) {
            LOG_ERR("Failed to read next TLV header: %d", rc);
            return UINT16_MAX;
        }

        offset += SHARED_DATA_ENTRY_HEADER_SIZE;
        if ((GET_MAJOR(tlv_entry.tlv_type) == major_type) &&
            (GET_MINOR(tlv_entry.tlv_type) == minor_type)) {
            if (buffer_len < tlv_entry.tlv_len) {
                LOG_ERR("Buffer is smaller than TLV data");
                return UINT16_MAX;
            }
            rc = retention_read(bootloader_info_dev, offset,
                                (void *)buffer, tlv_entry.tlv_len);
            if (rc) {
                LOG_ERR("Failed to read TLV's data: %d", rc);
                return UINT16_MAX;
            }
            return tlv_entry.tlv_len;
        }
        offset += tlv_entry.tlv_len;
    }
    return UINT16_MAX;
}
