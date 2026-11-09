### Changed

- **ci: the trusted-firmware `v0.4.2-alpha` pin moves to the commit the tag now peels to.** `scripts/tool-pins.sh` sets `TRUSTED_FIRMWARE_COMMIT` to `e0ae83d062b45dccc0e4cf08c87bf6def80a946c`, the commit trusted-firmware's rewritten history gives the unchanged tag, so `scripts/optee-fixture.sh` accepts the checkout again. The tag name, the fixture image pin and the refusal of a moved tag are unchanged.
