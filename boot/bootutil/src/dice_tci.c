/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#include <stdint.h>
#include "bootutil/bootutil_log.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/dice.h"
#include "bootutil/dice_tci.h"
#include "bootutil/image.h"
#include "bootutil_loader.h"
#include "bootutil_priv.h"
#include "mcuboot_config/mcuboot_config.h"

_Static_assert(DICE_TCI_SIZE == IMAGE_HASH_SIZE, "inconsistent hash algorithms");

BOOT_LOG_MODULE_REGISTER(dice_tci);

/* TODO Entangle hardware settings, such as whether JTAG is enabled */
int
dice_tci_get(struct boot_loader_state *state, uint8_t tci[static DICE_TCI_SIZE])
{
    const struct image_header *hdr;
    const struct flash_area *fap;
    int rc;
#if defined(EXPECTED_HASH_TLV) && !defined(MCUBOOT_SIGN_PURE)
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    uint16_t type;
#else
    TARGET_STATIC uint8_t tmpbuf[BOOT_TMPBUF_SZ];
#endif

    hdr = boot_img_hdr(state, BOOT_SLOT_PRIMARY);
    fap = BOOT_IMG_AREA(state, BOOT_SLOT_PRIMARY);
    assert(fap);

#if defined(EXPECTED_HASH_TLV) && !defined(MCUBOOT_SIGN_PURE)
    /* In this configuration, image_validate.c ensures that the hash TLV matches
     * the actual hash. So, we save time and just re-read the hash TLV. */
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, EXPECTED_HASH_TLV, false);
    if (rc) {
        BOOT_LOG_ERR("Failed to begin TLV iteration: %d", rc);
        return rc;
    }
    rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
    if (rc) {
        BOOT_LOG_ERR("Failed to find the expected hash TLV: %d", rc);
        return rc;
    }
    if (len != DICE_TCI_SIZE) {
        BOOT_LOG_ERR("The hash TLV has an invalid length");
        return -1;
    }
    rc = LOAD_IMAGE_DATA(hdr, fap, off, tci, DICE_TCI_SIZE);
    if (rc) {
        BOOT_LOG_ERR("Failed to read the hash TLV: %d", rc);
        return rc;
    }
#else
    rc = bootutil_img_hash(state,
                           hdr, fap,
                           tmpbuf, sizeof(tmpbuf),
                           tci, NULL, 0);
    if (rc) {
        BOOT_LOG_ERR("Failed to hash the primary image: %d", rc);
        return rc;
    }
#endif
    return 0;
}
