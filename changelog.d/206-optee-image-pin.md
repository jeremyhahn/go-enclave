### Changed

- Pin `OPTEE_FIXTURE_IMAGE` in `scripts/tool-pins.sh` to the public `ghcr.io/jeremyhahn/go-enclave-optee-fixture` image by manifest digest, published by the `ghcr-optee-fixture.yml` workflow (tag `v0.4.2-alpha-optee-4.11.0`), so the GitHub-hosted optee job pulls it without a login and runs the arm-trustzone harness; a buildgates test keeps the pin a ghcr digest (#206, #250).
