/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#ifndef H_DICE_RNG_
#define H_DICE_RNG_

#include <stdint.h>

struct boot_loader_state;

/**
 * Retrieves CDI_L0 from shared memory and seeds the RNG with CDI_L0.
 *
 * @return @c 0 on success and nonzero on failure.
 */
int dice_rng_init(void);

/**
 * Generates a cryptographic random number.
 *
 * @param dest The place to store the generated cryptographic random number.
 * @param size The length of the cryptographic random number to be generated.
 *
 * @return     @c 1 on success and @c 0 on failure.
 */
int dice_rng_rand(uint8_t *dest, unsigned size);

/**
 * Configures the RNG to use TCI_L1 as a salt.
 *
 * @param state Boot loader status information.
 *
 * @return      @c 0 on success, and nonzero otherwise.
 */
int dice_rng_set_salt(struct boot_loader_state *state);

/**
 * Provides the current salt.
 *
 * @return The current salt of @c DICE_TCI_SIZE bytes.
 */
const uint8_t *dice_rng_get_salt(void);

#endif /* H_DICE_RNG_ */
