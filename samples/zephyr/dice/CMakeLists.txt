# Copyright (c) 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(dice)

cmake_path(SET MCUBOOT_DIR "../../..")
cmake_path(SET LIBCOAP_DIR "${MCUBOOT_DIR}/ext/libcoap")
cmake_path(SET MICRO_ECC_DIR "${LIBCOAP_DIR}/ext/micro-ecc")

target_include_directories(app
  PRIVATE
    ${MCUBOOT_DIR}/boot/bootutil/include
    ${LIBCOAP_DIR}/include
    ${MICRO_ECC_DIR}
  )
target_sources(app
  PRIVATE
    src/main.c
    ${LIBCOAP_DIR}/src/oscore-ng/oscore_ng_cbor.c
    ${LIBCOAP_DIR}/src/oscore-ng/oscore_ng_tiny_dice.c
    ${MICRO_ECC_DIR}/uECC.c
  )
target_compile_definitions(app
  PRIVATE
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_ENABLE_VLI_API=1
  )
