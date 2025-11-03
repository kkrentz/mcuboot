# CMakeLists.txt for building the script for issuing a TinyDICE Cert_L0
#
# Copyright (c) 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20)
project(TinyDICE-CA C)

set(APP tiny-dice-ca)

cmake_path(SET MCUBOOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../")
cmake_path(SET LIBCOAP_DIR "${MCUBOOT_DIR}/ext/libcoap")
cmake_path(SET MICRO_ECC_DIR "${LIBCOAP_DIR}/ext/micro-ecc")
cmake_path(SET BOOTUTIL_DIR "${MCUBOOT_DIR}/boot/bootutil")
cmake_path(SET MBEDTLS_DIR "${MCUBOOT_DIR}/ext/mbedtls")

add_executable(${APP}
  tiny_dice_ca.c
  ${LIBCOAP_DIR}/src/oscore-ng/oscore_ng_cbor.c
  ${LIBCOAP_DIR}/src/oscore-ng/oscore_ng_tiny_dice.c
  ${MBEDTLS_DIR}/library/base64.c
  ${MBEDTLS_DIR}/library/platform_util.c
  ${MBEDTLS_DIR}/library/sha256.c
  ${MICRO_ECC_DIR}/uECC.c
  )

target_compile_definitions(${APP}
  PRIVATE uECC_CURVE=uECC_secp256r1
  PRIVATE uECC_SUPPORTS_secp160r1=0
  PRIVATE uECC_SUPPORTS_secp192r1=0
  PRIVATE uECC_SUPPORTS_secp224r1=0
  PRIVATE uECC_SUPPORTS_secp256r1=1
  PRIVATE uECC_SUPPORTS_secp256k1=0
  PRIVATE uECC_ENABLE_VLI_API=1
  )

target_include_directories(${APP}
  PRIVATE .
  PRIVATE ${BOOTUTIL_DIR}/include
  PRIVATE ${LIBCOAP_DIR}/include
  PRIVATE ${MBEDTLS_DIR}/include
  PRIVATE ${MICRO_ECC_DIR}
  )
