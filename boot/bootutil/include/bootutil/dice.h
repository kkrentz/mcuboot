/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#ifndef H_DICE_
#define H_DICE_

#include "coap3/coap_libcoap_build.h"

enum dice_version {
    DICE_VERSION_OPEN = 0, /* Google's Open Profile for DICE */
    DICE_VERSION_TINY, /* Siemens' ECQV-based version */
};

#define DICE_VERSION DICE_VERSION_TINY /* fixed to TinyDICE for now */

#if DICE_VERSION == DICE_VERSION_TINY
#define DICE_UDS_SIZE TINY_DICE_UDS_SIZE
#define DICE_CDI_SIZE TINY_DICE_CDI_SIZE
#define DICE_TCI_SIZE TINY_DICE_TCI_SIZE
#define DICE_CURVE uECC_secp256r1()
#define DICE_CURVE_SIZE ECC_CURVE_P_256_SIZE
#define DICE_SHARED_DATA_L0_MAX \
    (CBOR_UNSIGNED_SIZE((unsigned)DICE_VERSION) + /* DICE version */ \
     CBOR_BYTE_STRING_SIZE(2 * DICE_CURVE_SIZE) + /* DeviceID public key */ \
     TINY_DICE_MAX_CERT_CHAIN_SIZE + /* Certificate(s) */ \
     CBOR_BYTE_STRING_SIZE(2 * DICE_CURVE_SIZE) + /* AKey_L0 public key */ \
     CBOR_BYTE_STRING_SIZE(DICE_CURVE_SIZE) + /* AKey_L0 private key */ \
     CBOR_BYTE_STRING_SIZE(DICE_CDI_SIZE)) /* CDI_L1 */
#endif /* DICE_VERSION == DICE_VERSION_TINY */

#endif /* H_DICE_L0_ */
