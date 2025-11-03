/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Siemens AG
 */

#ifndef H_DICE_ROT_
#define H_DICE_ROT_

struct boot_loader_state;

/**
 * Performs the steps of DICE's root of trust.
 *
 * @param state Boot loader status information.
 *
 * @return      @c 0 on success, and nonzero otherwise.
 */
int dice_rot_boot(struct boot_loader_state *state);

#endif /* H_DICE_ROT_ */
