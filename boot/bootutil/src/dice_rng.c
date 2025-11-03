/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#include <stdint.h>
#include <string.h>
#include "bootutil/boot_record.h"
#include "bootutil/boot_status.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/dice.h"
#include "bootutil/dice_rng.h"
#include "bootutil/dice_tci.h"
#include "bootutil/image.h"
#include "uECC.h"

_Static_assert(DICE_CDI_SIZE >= BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE,
               "insufficient CDI size");

static uint8_t cdi_l0[DICE_CDI_SIZE];
static STRUCT_PACKED info {
    uint32_t counter;
    uint8_t tci_l1[DICE_TCI_SIZE];
} info;

int
dice_rng_init(void)
{
    return sizeof(cdi_l0)
           != boot_load_shared_data(TLV_MAJOR_BLINFO, BLINFO_DICE,
                                    cdi_l0, sizeof(cdi_l0));
}

int
dice_rng_rand(uint8_t *dest, unsigned size)
{
    if (bootutil_sha_hkdf_expand(cdi_l0, sizeof(cdi_l0),
                                 (const uint8_t *)&info, sizeof(info),
                                 dest, size)) {
        return 0;
    }
    info.counter++;
    return 1;
}

int
dice_rng_set_salt(struct boot_loader_state *const state)
{
    return dice_tci_get(state, info.tci_l1);
}

const uint8_t *
dice_rng_get_salt(void)
{
    return info.tci_l1;
}
