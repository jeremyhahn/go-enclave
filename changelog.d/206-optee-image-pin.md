### Changed

- Pin `OPTEE_FIXTURE_IMAGE` in `scripts/tool-pins.sh` to the OP-TEE fixture image Infra published (tag `v0.4.2-alpha-optee-4.11.0`, OCI index digest), so the CI optee job runs the arm-trustzone harness (#206, #250).
- Waive the releasability gate's lab-address check on the `OPTEE_FIXTURE_IMAGE` pin with a `lab-string-ok` comment: the optee job pulls the image from the lab registry by digest (#206, #250).
