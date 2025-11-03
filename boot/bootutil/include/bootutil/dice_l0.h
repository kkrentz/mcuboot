/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#ifndef H_DICE_L0_
#define H_DICE_L0_

struct boot_loader_state;

/**
 * Performs the steps of DICE's Layer 0.
 *
 * @param state Boot loader status information.
 *
 * @return      @c 0 on success, and nonzero otherwise.
 */
int dice_l0_boot(struct boot_loader_state *state);

#endif /* H_DICE_L0_ */
