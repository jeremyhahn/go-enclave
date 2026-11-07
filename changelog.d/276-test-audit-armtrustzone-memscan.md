### Changed

- The unit tests of the arm-trustzone backend (backend, client, TEE device) and of the memory-scanning test helper are audited against the integration suite and all kept, since none repeats an integration test or tests the standard library (#276). Nothing changes for Go callers.
