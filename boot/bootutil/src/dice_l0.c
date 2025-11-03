/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "bootutil/bootutil_log.h"
#include "bootutil/boot_record.h"
#include "bootutil/boot_status.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/dice.h"
#include "bootutil/dice_l0.h"
#include "bootutil/dice_rng.h"
#include "bootutil/image.h"
#include "bootutil_priv.h"
#include "coap3/coap_libcoap_build.h"
#include "mcuboot_config/mcuboot_config.h"
#include "uECC.h"

#define MAX_DICE_TLV_VALUE_LEN \
    (TINY_DICE_MAX_CERT_SIZE /* Cert_L0 */ \
     + CBOR_BYTE_STRING_SIZE(DICE_CURVE_SIZE)) /* s_L0 */

_Static_assert(IMAGE_HASH_SIZE >= DICE_CURVE_SIZE, "insufficient hash algorithm");

BOOT_LOG_MODULE_REGISTER(dice_l0);

struct dice_tlv {
    uint8_t tlv_value[MAX_DICE_TLV_VALUE_LEN];
    const uint8_t *cert_l0_bytes;
    size_t cert_l0_size;
    const uint8_t *private_key_reconstruction_data_l0; /* aka s_L0 */
    const uint8_t *subject_data;
    const char *subject_text;
    size_t subject_size;
};

struct cert_l1 {
    tiny_dice_cert_t cert;
    uint8_t bytes[TINY_DICE_MAX_CERT_SIZE];
    size_t size;
    uint8_t hash[IMAGE_HASH_SIZE];
};

/**
 * Loads the DICE TLV of our own image.
 *
 * @param state        Boot loader status information.
 * @param value        Buffer for storing the value of the DICE TLV.
 * @param is_protected Tells whether the DICE TLV is protected.
 *
 * @return             @c 0 on error and else the length of the DICE TLV.
 */
static uint_fast16_t
load_dice_tlv(const struct boot_loader_state *state,
              uint8_t value[static MAX_DICE_TLV_VALUE_LEN],
              bool *const is_protected)
{
    const struct image_header *hdr;
    const struct flash_area *fap;
    int rc;
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    uint16_t type;

    hdr = &state->bootloader.hdr;
    fap = state->bootloader.area;
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_DICE, false);
    if (rc) {
        BOOT_LOG_ERR("Failed to begin TLV iteration: %d", rc);
        return 0;
    }
    rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
    if (rc) {
        if (rc < 0) {
            BOOT_LOG_ERR("TLV iteration failed: %d", rc);
        } else {
            BOOT_LOG_DBG("Primary image lacks DICE TLV");
        }
        return 0;
    }
    if (len > MAX_DICE_TLV_VALUE_LEN) {
        BOOT_LOG_ERR("Length of TLV exceeds buffer size");
        return 0;
    }
    *is_protected = bootutil_tlv_iter_is_prot(&it, off);
    rc = LOAD_IMAGE_DATA(hdr, fap, off, value, len);
    return len;
}

/**
 * Extracts the subject field from a protected DICE TLV.
 *
 * @param reader   An initialized CBOR reader.
 * @param dice_tlv Structure for storing the subject.
 *
 * @return         @c 0 on success and nonzero otherwise.
 */
static int
parse_protected_dice_tlv(cbor_reader_state_t *const reader, struct dice_tlv *const dice_tlv)
{
    switch (cbor_peek_next(reader)) {
    case CBOR_MAJOR_TYPE_BYTE_STRING:
        dice_tlv->subject_data = cbor_read_data(reader, &dice_tlv->subject_size);
        dice_tlv->subject_text = NULL;
        return dice_tlv->subject_data == NULL;
    case CBOR_MAJOR_TYPE_TEXT_STRING:
        dice_tlv->subject_text = cbor_read_text(reader, &dice_tlv->subject_size);
        dice_tlv->subject_data = NULL;
        return dice_tlv->subject_text == NULL;
    default:
        return 1;
    }
}

/**
 * Extracts Cert_L0, s_L0, and the subject from an unprotected DICE TLV.
 *
 * @param reader   An initialized CBOR reader.
 * @param dice_tlv Structure for storing Cert_L0, s_L0, and the subject.
 *
 * @return         @c 0 on success and nonzero otherwise.
 */
static int
parse_unprotected_dice_tlv(cbor_reader_state_t *const reader, struct dice_tlv *const dice_tlv)
{
    tiny_dice_cert_t cert_l0;
    size_t s_l0_size;

    /* Parse Cert_L0 */
    dice_tlv->cert_l0_bytes = reader->cbor;
    if (!tiny_dice_decode_cert(reader, &cert_l0)) {
        BOOT_LOG_ERR("Failed to parse Cert_L0");
        return 1;
    }
    if (cert_l0.curve != TINY_DICE_CURVE_SECP256R1) {
        BOOT_LOG_ERR("Cert_L0 uses an unsupported curve");
        return 1;
    }
    if (cert_l0.issuer_hash != TINY_DICE_HASH_SHA256) {
        BOOT_LOG_ERR("Cert_L0 uses an unsupported hash algorithm");
        return 1;
    }
    dice_tlv->cert_l0_size = reader->cbor - dice_tlv->cert_l0_bytes;
    dice_tlv->subject_data = cert_l0.subject_data;
    dice_tlv->subject_text = cert_l0.subject_text;
    dice_tlv->subject_size = cert_l0.subject_size;

    /* Parse s_L0 */
    dice_tlv->private_key_reconstruction_data_l0 = cbor_read_data(reader, &s_l0_size);
    if (!dice_tlv->private_key_reconstruction_data_l0 || (DICE_CURVE_SIZE != s_l0_size)) {
        BOOT_LOG_ERR("Failed to parse s_L0");
        return 1;
    }
    return 0;
}

/**
 * Reads the DICE TLV from our own image.
 *
 * @param state    Boot loader status information.
 * @param dice_tlv Structure for storing the contents of the DICE TLV.
 *
 * @return         @c on success and nonzero otherwise.
 */
static int
read_dice_tlv(struct boot_loader_state *const state,
              struct dice_tlv *const dice_tlv)
{
    uint_fast16_t dice_tlv_len;
    bool is_protected;
    cbor_reader_state_t reader;
    int rc;

    /* load DICE TLV */
    dice_tlv_len = load_dice_tlv(state, dice_tlv->tlv_value, &is_protected);
    if (!dice_tlv_len) {
        BOOT_LOG_WRN("Found no DICE TLV");
        dice_tlv->cert_l0_bytes = NULL;
        dice_tlv->cert_l0_size = 0;
        dice_tlv->private_key_reconstruction_data_l0 = NULL;
        dice_tlv->subject_data = NULL;
        dice_tlv->subject_text = NULL;
        dice_tlv->subject_size = 0;
        return 0;
    }

    /* parse DICE TLV */
    cbor_init_reader(&reader, dice_tlv->tlv_value, dice_tlv_len);
    if (is_protected) {
        dice_tlv->cert_l0_bytes = NULL;
        dice_tlv->cert_l0_size = 0;
        dice_tlv->private_key_reconstruction_data_l0 = NULL;
        rc = parse_protected_dice_tlv(&reader, dice_tlv);
        if (rc) {
            BOOT_LOG_ERR("Failed to parse protected DICE TLV: %d", rc);
            return 1;
        }
        BOOT_LOG_DBG("Extracted subject from DICE TLV");
    } else {
        rc = parse_unprotected_dice_tlv(&reader, dice_tlv);
        if (rc) {
            BOOT_LOG_ERR("Failed to parse unprotected DICE TLV: %d", rc);
            return 1;
        }
        BOOT_LOG_DBG("Extracted Cert_L0 and s_L0 from DICE TLV");
    }
    if (!cbor_end_reader(&reader)) {
        BOOT_LOG_WRN("Unread bytes remain in DICE TLV");
    }
    return 0;
}

/**
 * Encodes and hashes Cert_L1.
 *
 * @param reconstruction_data Data for reconstructing AKey_L0.
 * @param opaque              Pointer to partial information about Cert_L1.
 * @param certificate_hash    The resultant digest of DICE_CURVE_SIZE bytes.
 *
 * @return                    @c 1 on success and @c 0 otherwise.
 */
static int
encode_and_hash_cert_l1(const uint8_t *reconstruction_data,
                        void *opaque,
                        uint8_t *certificate_hash)
{
    struct cert_l1 *cert_l1;
    cbor_writer_state_t state;

    cert_l1 = (struct cert_l1 *)opaque;
    uECC_compress(reconstruction_data, cert_l1->cert.reconstruction_data, DICE_CURVE);

    /* Encode Cert_L1 */
    cbor_init_writer(&state, cert_l1->bytes, sizeof(cert_l1->bytes));
    tiny_dice_write_cert(&state, &cert_l1->cert);
    cert_l1->size = cbor_end_writer(&state);
    if (!cert_l1->size) {
        BOOT_LOG_ERR("Failed to encode Cert_L1");
        return 0;
    }
    BOOT_LOG_DBG("Cert_L1 has %zu bytes at rest", cert_l1->size);

    /* Hash Cert_L1 */
    if (bootutil_sha(cert_l1->bytes, cert_l1->size, cert_l1->hash)) {
        BOOT_LOG_ERR("Failed to hash Cert_L1");
        return 0;
    }
    memcpy(certificate_hash, cert_l1->hash, DICE_CURVE_SIZE);
    return 1;
}

/**
 * Places AKey_L0 and the corresponding certificate chain in retained memory.
 *
 * @param proto_device_id_public_key Public portion of (proto-)DeviceID.
 * @param akey_l0_public_key         Public portion of AKey_L0.
 * @param akey_l0_private_key        Private portion of AKey_L0.
 * @param dice_tlv                   Contents of the DICE TLV.
 * @param cert_l1              I     Information about Cert_L1.
 *
 * @return                           @c 0 on success and nonzero otherwise.
 */
static int
pass_dice_data_to_layer_1(const uint8_t proto_device_id_public_key[static 2 * DICE_CURVE_SIZE],
                          const uint8_t akey_l0_public_key[static 2 * DICE_CURVE_SIZE],
                          const uint8_t akey_l0_private_key[static DICE_CURVE_SIZE],
                          const struct dice_tlv *const dice_tlv,
                          const struct cert_l1 *const cert_l1)
{
    cbor_writer_state_t writer;
    uint8_t cbor[DICE_SHARED_DATA_L0_MAX];
    uint8_t cdi_l1[DICE_CDI_SIZE];
    size_t cbor_len;

    cbor_init_writer(&writer, cbor, sizeof(cbor));
    cbor_write_unsigned(&writer, DICE_VERSION);
    cbor_write_data(&writer, proto_device_id_public_key, 2 * DICE_CURVE_SIZE);
    cbor_open_array(&writer);
    if (dice_tlv->cert_l0_size) {
        cbor_write_object(&writer, dice_tlv->cert_l0_bytes, dice_tlv->cert_l0_size);
    }
    cbor_write_object(&writer, cert_l1->bytes, cert_l1->size);
    cbor_close_array(&writer);
    cbor_write_data(&writer, akey_l0_public_key, 2 * DICE_CURVE_SIZE);
    cbor_write_data(&writer, akey_l0_private_key, DICE_CURVE_SIZE);
    if (!dice_rng_rand(cdi_l1, sizeof(cdi_l1))) {
        LOG_WRN("Failed to generate CDI_L1");
    } else {
        cbor_write_data(&writer, cdi_l1, sizeof(cdi_l1));
    }
    cbor_len = cbor_end_writer(&writer);
    if (!cbor_len) {
        BOOT_LOG_ERR("Failed to encode data for Layer 1");
        return 1;
    }
    return boot_add_data_to_shared_area(TLV_MAJOR_BLINFO, BLINFO_DICE, cbor_len, cbor);
}

int
dice_l0_boot(struct boot_loader_state *const state)
{
    int rc;
    struct dice_tlv dice_tlv;
    uint8_t proto_device_id_public_key[2 * DICE_CURVE_SIZE];
    uint8_t proto_device_id_private_key[DICE_CURVE_SIZE];
    uint8_t proto_akey_l0_public_key[2 * DICE_CURVE_SIZE];
    uint8_t proto_akey_l0_private_key[DICE_CURVE_SIZE];
    uint8_t cert_l0_hash[IMAGE_HASH_SIZE];
    uint8_t dummy[2 * DICE_CURVE_SIZE];
    struct cert_l1 cert_l1;
    uint8_t private_key_reconstruction_data_l1[DICE_CURVE_SIZE]; /* aka s_L1 */
    uint8_t akey_l0_public_key[2 * DICE_CURVE_SIZE];
    uint8_t akey_l0_private_key[DICE_CURVE_SIZE];

    /* Read DICE TLV */
    rc = read_dice_tlv(state, &dice_tlv);
    if (rc) {
        BOOT_LOG_ERR("Failed to read DICE TLV: %d", rc);
        return 1;
    }

    /* Switch to deterministic RNG */
    rc = dice_rng_init();
    if (rc) {
        BOOT_LOG_ERR("Failed to initialize deterministic RNG: %d", rc);
        return 1;
    }

    /* Generate (proto-)DeviceID */
    if (!uECC_make_key_deterministic(dice_rng_rand,
                                     proto_device_id_public_key,
                                     proto_device_id_private_key,
                                     DICE_CURVE)) {
        BOOT_LOG_ERR("Failed to generate (proto-)DeviceID");
        return 1;
    }

    /* Use TCI_L1 as salt */
    rc = dice_rng_set_salt(state);
    if (rc) {
        BOOT_LOG_ERR("Failed to set salt: %d", rc);
        return rc;
    }

    /* Generate proto-AKey_L0 */
    if (!uECC_make_key_deterministic(dice_rng_rand,
                                     proto_akey_l0_public_key,
                                     proto_akey_l0_private_key,
                                     DICE_CURVE)) {
        BOOT_LOG_ERR("Failed to generate AKey_L0");
        return 1;
    }

    /* Reconstruct DeviceID */
    if (dice_tlv.cert_l0_size) {
        if (bootutil_sha(dice_tlv.cert_l0_bytes, dice_tlv.cert_l0_size, cert_l0_hash)) {
            BOOT_LOG_ERR("Failed to hash Cert_L0");
            return 1;
        }
        if (!uECC_generate_ecqv_key_pair(proto_device_id_private_key,
                                         cert_l0_hash,
                                         sizeof(cert_l0_hash),
                                         dice_tlv.private_key_reconstruction_data_l0,
                                         dummy,
                                         proto_device_id_private_key,
                                         DICE_CURVE)) {
            BOOT_LOG_ERR("Failed to reconstruct DeviceID");
            return 1;
        }
    }

    /* Initialize Cert_L1 partially */
    tiny_dice_clear_cert(&cert_l1.cert);
    cert_l1.cert.subject_text = dice_tlv.subject_text;
    cert_l1.cert.subject_data = dice_tlv.subject_data;
    cert_l1.cert.subject_size = dice_tlv.subject_size;
    if (dice_tlv.cert_l0_size) {
        cert_l1.cert.issuer_id = cert_l0_hash;
    }
    cert_l1.cert.tci_digest = dice_rng_get_salt();

    /* Issue Cert_L1 */
    do {
        if (!uECC_issue_ecqv_certificate(proto_akey_l0_public_key,
                                         proto_device_id_private_key,
                                         encode_and_hash_cert_l1,
                                         &cert_l1,
                                         private_key_reconstruction_data_l1,
                                         DICE_CURVE)) {
            BOOT_LOG_ERR("Failed to issue Cert_L1");
            return 1;
        }

        /* Reconstruct AKey_L0 */
    } while (!uECC_generate_ecqv_key_pair(proto_akey_l0_private_key,
                                          cert_l1.hash,
                                          sizeof(cert_l1.hash),
                                          private_key_reconstruction_data_l1,
                                          akey_l0_public_key,
                                          akey_l0_private_key,
                                          DICE_CURVE));

    /* Hand over to Layer 1 */
    return pass_dice_data_to_layer_1(proto_device_id_public_key,
                                     akey_l0_public_key,
                                     akey_l0_private_key,
                                     &dice_tlv,
                                     &cert_l1);
}
