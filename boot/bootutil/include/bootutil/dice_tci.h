/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#ifndef H_DICE_TCI_
#define H_DICE_TCI_

#include <stdint.h>
#include "bootutil/dice.h"

struct boot_loader_state;

/**
 * Hashes the next layer's software and the hardware configuration at start up.
 *
 * @param state Pointer to the boot state object.
 * @param hash  Buffer for storing the TCI.
 *
 * @return      @c 0 on success and nonzero otherwise.
 */
int dice_tci_get(struct boot_loader_state *state, uint8_t tci[static DICE_TCI_SIZE]);

#endif /* H_DICE_TCI_ */
