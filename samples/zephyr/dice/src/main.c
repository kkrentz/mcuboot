/*
 * Copyright (c) 2025 Siemens AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bootutil/dice.h"
#include "coap3/coap_libcoap_build.h"
#include "mbedtls/sha256.h"
#include "uECC.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <zephyr/settings/settings.h>

struct shared_data {
    enum dice_version dice_version;
    const uint8_t *proto_device_id_public_key;
    size_t proto_device_id_public_key_size;
    tiny_dice_cert_chain_t cert_chain;
    const uint8_t *akey_l0_public_key;
    size_t akey_l0_public_key_size;
    const uint8_t *akey_l0_private_key;
    size_t akey_l0_private_key_size;
    size_t cdi_l1_size;
    const uint8_t *cdi_l1;
};

static const uint32_t trusted_tci_l0_version = 1;
static const uint8_t ca_public_key[2 * ECC_CURVE_P_256_SIZE] = {
    0xd4, 0xb3, 0xcd, 0x4c, 0xb9, 0xde, 0xee, 0x08,
    0x9f, 0xdd, 0x7b, 0x5e, 0x61, 0x93, 0xc0, 0xf7,
    0x6f, 0x17, 0x11, 0x12, 0x25, 0x99, 0x47, 0xa3,
    0x9e, 0x40, 0xfd, 0xeb, 0xad, 0x8f, 0x4e, 0x0e,
    0xb6, 0x74, 0xee, 0x05, 0xf5, 0xdb, 0x8a, 0xaa,
    0x4d, 0x14, 0xc2, 0x51, 0x74, 0x8f, 0x90, 0x71,
    0x28, 0xb8, 0xe5, 0x15, 0xb9, 0xdf, 0x8d, 0xed,
    0x50, 0xa1, 0x75, 0x7d, 0x18, 0xed, 0x3e, 0x6f
};

static void
dump_bytes(const uint8_t *const bytes, size_t bytes_size)
{
    for (size_t i = 0; i < bytes_size; i++) {
        printf("%02x", bytes[i]);
    }
}

static void
dump_cert_chain(const tiny_dice_cert_chain_t *const cert_chain)
{
    for (size_t i = 0; i < cert_chain->length; i++) {
        const tiny_dice_cert_t *cert = cert_chain->certs + i;

        if (!i && cert_chain->length == 2) {
            printf("Cert_L0: ");
        } else {
            printf("Cert_L1: ");
        }
        printf("{\n");

        /* subject */
        if (cert->subject_size) {
            printf("  subject: ");
            if (cert->subject_data) {
                dump_bytes(cert->subject_data, cert->subject_size);
            } else {
                printf("\"");
                for (size_t j = 0; j < cert->subject_size; j++) {
                    printf("%c", cert->subject_text[j]);
                }
                printf("\"");
            }
            printf(",\n");
        }

        /* issuer */
        if (cert->issuer_id) {
            printf("  issuer: ");
            dump_bytes(cert->issuer_id, TINY_DICE_ISSUER_ID_SIZE);
            printf(",\n");
        } else if (cert->issuer_hash == TINY_DICE_HASH_SHA256) {
            printf("  issuer: %i (SHA-256),\n", TINY_DICE_HASH_SHA256);
        }

        /* curve */
        if (cert->curve == TINY_DICE_CURVE_SECP256R1) {
            printf("  curve: %i (secp256r1),\n", TINY_DICE_CURVE_SECP256R1);
        }

        /* reconstruction-data */
        printf("  reconstruction-data: ");
        dump_bytes(cert->reconstruction_data, sizeof(cert->reconstruction_data));
        printf(",\n");

        /* tci */
        if (cert->tci_digest) {
            printf("  tci: ");
            dump_bytes(cert->tci_digest, TINY_DICE_TCI_SIZE);
            printf("\n");
        } else if (cert->tci_version) {
            printf("  tci: %" PRIu32 "\n", cert->tci_version);
        }

        printf("}\n");
    }
}

/**
 * Parses the CBOR Sequence that was received from Layer 0 via retained memory.
 *
 * That CBOR Sequence has the following CDDL description:
 *
 * dice_info = [ ; CBOR Sequence of:
 *    dice_version : &dice_versions,
 *    device_id_public_key : bstr,
 *    certificates : [ + certificate ],
 *    akey_public_key : bstr,
 *    akey_private_key : bstr,
 *    ? cdi : bstr
 * ]
 *
 * dice_versions = (
 *   open_dice: 0,
 *   tiny_dice: 1,
 * )
 *
 * As for TinyDICE, please find the CDDL description of `certificate` in our
 * paper. As for the Open Profile for DICE, see the specification. However,
 * for the time being, only TinyDICE is supported.
 */
static int
parse_shared_data(const uint8_t *const shared_data_bytes, size_t shared_data_size,
                  struct shared_data *const shared_data)
{
    /* Initialize CBOR reader */
    cbor_reader_state_t reader;
    cbor_init_reader(&reader, shared_data_bytes, shared_data_size);

    /* Parse DICE version */
    uint64_t version;
    if (cbor_read_unsigned(&reader, &version) == CBOR_SIZE_NONE) {
        printf("Error parsing DICE version\n");
        return 1;
    }
    if (version != DICE_VERSION_TINY) {
        printf("Unsupported version of DICE\n");
        return 1;
    }
    shared_data->dice_version = version;

    /* Parse public portion of (proto-)DeviceID */
    shared_data->proto_device_id_public_key =
            cbor_read_data(&reader, &shared_data->proto_device_id_public_key_size);
    if (!shared_data->proto_device_id_public_key) {
        printf("Error parsing public portion of (proto-)DeviceID\n");
        return 1;
    }

    /* Parse TinyDICE certificate chain */
    if (tiny_dice_decode_cert_chain(&reader, &shared_data->cert_chain) == SIZE_MAX) {
        printf("Error parsing TinyDICE certificate chain\n");
        return 1;
    }

    /* Parse public portion of AKey_L0 */
    shared_data->akey_l0_public_key =
            cbor_read_data(&reader, &shared_data->akey_l0_public_key_size);
    if (!shared_data->akey_l0_public_key) {
        printf("Error parsing public portion of AKey_L0\n");
        return 1;
    }

    /* Parse private portion of AKey_L0 */
    shared_data->akey_l0_private_key =
            cbor_read_data(&reader, &shared_data->akey_l0_private_key_size);
    if (!shared_data->akey_l0_private_key) {
        printf("Error parsing private portion of AKey_L0\n");
        return 1;
    }

    /* Parse CDI_L1 */
    if (cbor_peek_next(&reader) == CBOR_MAJOR_TYPE_BYTE_STRING) {
        shared_data->cdi_l1 = cbor_read_data(&reader, &shared_data->cdi_l1_size);
        if (!shared_data->cdi_l1) {
            printf("Error parsing CDI_L1\n");
            return 1;
        }
    } else {
        shared_data->cdi_l1 = NULL;
        shared_data->cdi_l1_size = 0;
    }

    /* Ensure that no unread bytes remain */
    if (!cbor_end_reader(&reader)) {
        printf("Unread bytes remain\n");
        return 1;
    }
    return 0;
}

static void
dump_shared_data(struct shared_data *const shared_data)
{
    uint8_t compressed[1 + ECC_CURVE_P_256_SIZE];

    /* Dump public portion of (proto-)DeviceID */
    printf("Public (proto-)DeviceID: ");
    uECC_compress(shared_data->proto_device_id_public_key, compressed, uECC_secp256r1());
    dump_bytes(compressed, sizeof(compressed));
    printf("\n");

    /* Dump certificate chain */
    dump_cert_chain(&shared_data->cert_chain);

    /* Dump public portion of AKey_L0 */
    printf("AKey_L0 (public): ");
    uECC_compress(shared_data->akey_l0_public_key, compressed, uECC_secp256r1());
    dump_bytes(compressed, sizeof(compressed));
    printf("\n");

    /* Dump private portion of AKey_L0 */
    printf("AKey_L0 (private): ");
    dump_bytes(shared_data->akey_l0_private_key, shared_data->akey_l0_private_key_size);
    printf("\n");

    /* Dump CDI_L1 */
    printf("CDI_L1: ");
    dump_bytes(shared_data->cdi_l1, shared_data->cdi_l1_size);
    printf("\n");
}

static int
validate_shared_data(struct shared_data *const shared_data)
{
    /* Validate length of certificate chain */
    if (!shared_data->cert_chain.length || (shared_data->cert_chain.length > 2)) {
        printf("Encountered an unexpected number of certificates\n");
        return 1;
    }

    uint8_t last_reconstructed_public_key[2 * ECC_CURVE_P_256_SIZE];
    for (size_t i = 0; i < shared_data->cert_chain.length; i++) {
        const tiny_dice_cert_t *const current_cert = shared_data->cert_chain.certs + i;

        /* Validate TCIs */
        if ((shared_data->cert_chain.length > 1) && !i) {
            if (current_cert->tci_version != trusted_tci_l0_version) {
                printf("Untrusted TCI_L0\n");
                return 1;
            }
        } else {
            /* accept any TCI_L1 in this demo */
        }

        /* Spell out and hash certificate */
        uint8_t cert[TINY_DICE_MAX_CERT_SIZE];
        cbor_writer_state_t state;
        cbor_init_writer(&state, cert, sizeof(cert));
        tiny_dice_write_cert(&state, current_cert);
        size_t cert_size = cbor_end_writer(&state);
        if (!cert_size) {
            printf("Failed to spell out certificate\n");
            return 1;
        }
        uint8_t cert_hash[SHA_256_DIGEST_LENGTH];
        if (mbedtls_sha256(cert, cert_size, cert_hash, 0) < 0) {
            printf("Failed to hash certificate\n");
            return 1;
        }

        uint8_t current_ca_public_key[2 * ECC_CURVE_P_256_SIZE];
        if (i) {
            /* Use public portion of reconstructed DeviceID */
            memcpy(current_ca_public_key, last_reconstructed_public_key, sizeof(current_ca_public_key));
        } else if (shared_data->cert_chain.length > 1) {
            /* Use CA's public key */
            memcpy(current_ca_public_key, ca_public_key, sizeof(current_ca_public_key));
        } else {
            /* Use public portion of DeviceID */
            memcpy(current_ca_public_key,
                   shared_data->proto_device_id_public_key,
                   sizeof(current_ca_public_key));
        }

        /* decompress reconstruction data */
        uECC_decompress(current_cert->reconstruction_data, last_reconstructed_public_key, uECC_secp256r1());

        /* validate reconstruction data */
        if (!uECC_valid_public_key(last_reconstructed_public_key, uECC_secp256r1())) {
            printf("uECC_valid_public_key failed\n");
            return 1;
        }

        /* reconstruct public key in place */
        uECC_reconstruct_ecqv_public_key(cert_hash,
                                         sizeof(cert_hash),
                                         last_reconstructed_public_key,
                                         current_ca_public_key,
                                         last_reconstructed_public_key,
                                         uECC_secp256r1());

    }

    /* Compare reconstructed AKey_L0 with the one received via retained memory */
    if (memcmp(last_reconstructed_public_key,
               shared_data->akey_l0_public_key,
               sizeof(last_reconstructed_public_key))) {
        printf("Failed to reconstruct AKey_L0\n");
        return 1;
    }
    printf("Succeeded to reconstruct AKey_L0\n");

    return 0;
}

int
main(void)
{
    /* Load shared data  */
    uint8_t shared_data_bytes[DICE_SHARED_DATA_L0_MAX];
    int shared_data_size =
            settings_runtime_get("blinfo/dice", shared_data_bytes, sizeof(shared_data_bytes));
    if (shared_data_size < 0) {
        printf("Error accessing shared data\n");
        return 1;
    }

    /* Parse shared data */
    struct shared_data shared_data;
    if (parse_shared_data(shared_data_bytes, shared_data_size, &shared_data)) {
        return 1;
    }

    /* Dump shared data */
    dump_shared_data(&shared_data);

    /* Validate shared data */
    return validate_shared_data(&shared_data);
}
