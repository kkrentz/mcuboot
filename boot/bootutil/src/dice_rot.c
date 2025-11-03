/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#include <stdint.h>
#include "bootutil/bootutil_log.h"
#include "bootutil/boot_record.h"
#include "bootutil/boot_status.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/dice.h"
#include "bootutil/dice_rot.h"
#include "bootutil/dice_tci.h"
#include "mcuboot_config/mcuboot_config.h"

_Static_assert(DICE_UDS_SIZE >= BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE,
               "insufficient UDS size");

BOOT_LOG_MODULE_REGISTER(dice_rot);

/* TODO Set to a device-specific symmetric key that only the RoT can access */
static uint8_t uds[DICE_UDS_SIZE];

int
dice_rot_boot(struct boot_loader_state *state)
{
    uint8_t cdi_l0[DICE_CDI_SIZE];
    uint8_t tci_l0[DICE_TCI_SIZE];
    int rc;

    /* Derive CDI_L0 from UDS and TCI_L0 */
    rc = dice_tci_get(state, tci_l0);
    if (rc) {
        BOOT_LOG_ERR("Failed to get TCI_L0");
        return rc;
    }
    rc = bootutil_sha_hkdf_expand(uds, sizeof(uds),
                                  tci_l0, sizeof(tci_l0),
                                  cdi_l0, sizeof(cdi_l0));
    if (rc) {
        BOOT_LOG_ERR("Failed to derive CDI_L0");
        return rc;
    }

    /* Place CDI_L0 in shared area */
    rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO, BLINFO_DICE,
                                      sizeof(cdi_l0), cdi_l0);
    if (rc) {
        BOOT_LOG_ERR("Failed to add CDI_L0 to shared area: %d", rc);
        return rc;
    }

    return 0;
}
