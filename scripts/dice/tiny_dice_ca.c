/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#include "coap3/coap_libcoap_build.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "uECC.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cert_l0 {
    uint8_t subject_buffer[TINY_DICE_MAX_SUBJECT_SIZE];
    tiny_dice_cert_t cert;
    uint8_t bytes[TINY_DICE_MAX_CERT_SIZE];
    size_t size;
    uint8_t reconstruction_data[ECC_CURVE_P_256_SIZE * 2];
    uint8_t hash[SHA_256_DIGEST_LENGTH];
};

static int
load_cas_private_key(uint8_t ca_private_key[static ECC_CURVE_P_256_SIZE],
                     const char *const filename)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        return 0;
    }
    char *b64 = NULL;
    size_t allocated_size;
    ssize_t b64_len = getline(&b64, &allocated_size, file);
    size_t ca_private_key_len;
    if ((b64_len == -1)
        || fclose(file)
        || mbedtls_base64_decode(ca_private_key, ECC_CURVE_P_256_SIZE,
                                 &ca_private_key_len,
                                 b64, b64_len)
        || (ca_private_key_len != ECC_CURVE_P_256_SIZE)) {
        free(b64);
        return 0;
    }
    free(b64);
    return 1;
}

static uint_fast8_t
hex_to_nibble(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }
    if ((c >= 'A') && (c <= 'F')) {
        return 10 + (c - 'A');
    }
    if ((c >= 'a') && (c <= 'f')) {
        return 10 + (c - 'a');
    }
    return UINT_FAST8_MAX;
}

static size_t
hex_to_bytes(const char *hex, size_t hex_len,
             uint8_t *const bytes, size_t bytes_len)
{
    if (hex_len & 1) {
        return SIZE_MAX;
    }
    if (!hex_len) {
        return 0;
    }
    if ((hex[0] == '0') && (hex[1] == 'x')) {
        /* Truncate "0x" prefix */
        hex += 2;
        hex_len -= 2;
    }
    size_t result_len = hex_len >> 1;
    if (result_len > bytes_len) {
        return SIZE_MAX;
    }
    for (size_t i = 0; i < hex_len; i += 2) {
        char high_nibble = hex_to_nibble(hex[i]);
        if (high_nibble == UINT_FAST8_MAX) {
            return SIZE_MAX;
        }
        char low_nibble = hex_to_nibble(hex[i + 1]);
        if (low_nibble == UINT_FAST8_MAX) {
            return SIZE_MAX;
        }
        uint_fast8_t value;
        bytes[i >> 1] = (high_nibble << 4) | low_nibble;
    }
    return result_len;
}

static int
initialize_subject(const char *const subject, struct cert_l0 *const cert_l0)
{
    size_t len = strlen(subject);
    if ((len >= 2) && (subject[0] == '0') && (subject[1] == 'x')) {
        /* Convert hex string to byte array */
        cert_l0->cert.subject_data = cert_l0->subject_buffer;
        cert_l0->cert.subject_size =
                hex_to_bytes(subject, len,
                             cert_l0->subject_buffer, sizeof(cert_l0->subject_buffer));
    } else {
        /* Use as text string */
        cert_l0->cert.subject_text = subject;
        cert_l0->cert.subject_size = len;
    }
    return cert_l0->cert.subject_size <= sizeof(cert_l0->subject_buffer);
}

static int
encode_and_hash_cert_l0(const uint8_t *const reconstruction_data,
                        void *const opaque,
                        uint8_t *const certificate_hash)
{
    struct cert_l0 *cert_l0 = (struct cert_l0 *)opaque;
    cbor_writer_state_t state;

    memcpy(cert_l0->reconstruction_data,
           reconstruction_data,
           sizeof(cert_l0->reconstruction_data));
    uECC_compress(reconstruction_data,
                  cert_l0->cert.reconstruction_data,
                  uECC_secp256r1());

    /* Encode Cert_L0 */
    cbor_init_writer(&state, cert_l0->bytes, sizeof(cert_l0->bytes));
    tiny_dice_write_cert(&state, &cert_l0->cert);
    cert_l0->size = cbor_end_writer(&state);
    if (!cert_l0->size) {
        printf("Failed to encode Cert_L0\n");
        return 0;
    }

    /* Hash Cert_L0 */
    if (mbedtls_sha256(cert_l0->bytes, cert_l0->size, cert_l0->hash, 0)) {
        printf("Failed to hash Cert_L0\n");
        return 0;
    }
    memcpy(certificate_hash, cert_l0->hash, ECC_CURVE_P_256_SIZE);
    return 1;
}

int
main(int argc, const char *argv[])
{
    if (argc != 5) {
        printf("usage: tiny-dice-ca <private key> <subject> <TCI_L0> <DeviceID>\n");
        printf("    private key: Private key of the certificate authority\n");
        printf("    subject:     Name of the device for which the certificate shall be issued\n");
        printf("    TCI_L0:      Version number of Layer 0 to certify\n");
        printf("    DeviceID:    Public portion of the DeviceID to certify\n");
        exit(EXIT_FAILURE);
    }

    /* Load CA's private key from file */
    uint8_t ca_private_key[ECC_CURVE_P_256_SIZE];
    if (!load_cas_private_key(ca_private_key, argv[1])) {
        printf("Failed to load CA's private key\n");
        exit(EXIT_FAILURE);
    }
    uint8_t ca_public_key[2 * ECC_CURVE_P_256_SIZE];
    if (!uECC_compute_public_key(ca_private_key, ca_public_key, uECC_secp256r1())) {
        printf("Failed to compute CA's public key\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize Cert_L0 partially */
    struct cert_l0 cert_l0;
    tiny_dice_clear_cert(&cert_l0.cert);
    if (!initialize_subject(argv[2], &cert_l0)) {
        printf("Failed to initialize subject\n");
        exit(EXIT_FAILURE);
    }
    cert_l0.cert.tci_version = strtoul(argv[3], NULL, 10);
    if (!cert_l0.cert.tci_version
        || (cert_l0.cert.tci_version == UINT32_MAX)) {
        printf("Invalid version\n");
        exit(EXIT_FAILURE);
    }

    /* Parse public (proto-)DeviceID */
    uint8_t public_device_id_compressed[1 + ECC_CURVE_P_256_SIZE];
    if (sizeof(public_device_id_compressed)
        != hex_to_bytes(argv[4], strlen(argv[4]),
                        public_device_id_compressed, sizeof(public_device_id_compressed))) {
        printf("Failed to parse public (proto-)DeviceID\n");
        exit(EXIT_FAILURE);
    }
    uint8_t public_device_id[2 * ECC_CURVE_P_256_SIZE];
    uECC_decompress(public_device_id_compressed, public_device_id, uECC_secp256r1());

    /* Issue Cert_L0 */
    uint8_t s_l0[ECC_CURVE_P_256_SIZE];
    uint8_t certified_public_key[2 * ECC_CURVE_P_256_SIZE];
    do {

      if (!uECC_issue_ecqv_certificate(public_device_id,
                                       ca_private_key,
                                       encode_and_hash_cert_l0,
                                       &cert_l0,
                                       s_l0,
                                       uECC_secp256r1())) {
          printf("Failed to issue Cert_L0\n");
          exit(EXIT_FAILURE);
      }

    } while (!uECC_reconstruct_ecqv_public_key(cert_l0.hash,
                                               sizeof(cert_l0.hash),
                                               cert_l0.reconstruction_data,
                                               ca_public_key,
                                               certified_public_key,
                                               uECC_secp256r1()));

    /* Encode s_L0 as CBOR byte array */
    uint8_t s_l0_cbor[CBOR_BYTE_STRING_SIZE(sizeof(s_l0))];
    cbor_writer_state_t writer;
    cbor_init_writer(&writer, s_l0_cbor, sizeof(s_l0_cbor));
    cbor_write_data(&writer, s_l0, sizeof(s_l0));
    if (sizeof(s_l0_cbor) != cbor_end_writer(&writer)) {
        printf("failed to encode s_L0\n");
        exit(EXIT_FAILURE);
    }

    /* Dump CBOR Sequence */
    printf("0x");
    for (size_t i = 0; i < cert_l0.size; i++) {
        printf("%02x", cert_l0.bytes[i]);
    }
    for (size_t i = 0; i < sizeof(s_l0_cbor); i++) {
        printf("%02x", s_l0_cbor[i]);
    }
    printf("\n");

    exit(EXIT_SUCCESS);
}
