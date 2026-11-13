# SPEC rows

One SPEC row = one row issue = one branch `row/<issue>-<row>` = one lane session = one PR (handbook `software/conventions/sdlc.md` §2b). Every open issue sits under its row issue or is listed below. Rows are in [docs/SPEC.md](../docs/SPEC.md) order.

| Row | Row issue | Status | Folded issues | Open PRs |
|---|---|---|---|---|
| memory-enclave | #448 | shipped | 0 | #447, #444, #404, #403 |
| locked-memory-budget | #449 | shipped | 1 | #391, #413 |
| sealing | #450 | shipped | 1 | #362, #446, #445, #406, #388 |
| keyprotector-providers | #264 | in progress | 3 | #384, #421, #374, #363, #358, #412, #411, #410, #409, #408 |
| shutdown-sweep | #451 | shipped | 0 | #405 |
| provider-conformance | #452 | shipped | 4 | #381, #428, #390, #379, #360 |
| backend-conformance | #453 | shipped | 3 | #427, #380, #359 |
| build-and-release | #454 | shipped | 6 | #425, #424, #423, #419, #418, #389, #364, #316, #443, #442, #441, #440, #439, #438, #437, #436, #435, #434, #433, #432, #431, #430, #401, #400, #399, #398, #397, #396 |
| backend-detection | #455 | shipped | 0 | #402 |
| public-release | #456 | in progress | 1 | #392, #365, #361 |
| linux-secretmem | #457 | shipped | 0 | #407 |
| mac-secure-enclave | #192 | future | 0 | #357 |
| arm-trustzone | #458 | shipped | 3 | #426, #422, #373, #429, #395, #394, #393 |
| intel-sgx | #193 | future | 0 | #353 |
| confidential-vm | #194 | future | 1 | #352, #354 |

Rows with no open work: `backends`, `enclave-interface`, `open-in-secretmem`, `imx-edgelock-enclave`.
