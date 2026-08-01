/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

    # Replacement for the RFC worked example: correct the PLL divider.
    # void patch_fn(trap_frame_t *frame); entry MUST be at image base.
    .section .text
    .globl patch_fn
patch_fn:
    csrr t1, mcycle     # CSR read (csrrs t1, mcycle, x0) -> allowed
    li   t0, 0x5        # correct divider
    sw   t0, 0(a0)      # frame->a0 = 5 (example)
    ret
