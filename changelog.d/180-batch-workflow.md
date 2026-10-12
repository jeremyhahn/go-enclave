### Added

- **A dispatch-only Batch workflow for the batch runners** (#180). `.github/workflows/batch.yml`, from the handbook's batch template, runs CPU work that gates nothing on `main`: fuzzing, the unit suite under the race detector three times, a soak loop of `make integration-test`, and the root package's benchmarks with allocation counts. Each finding is printed on a `BATCH-FINDING` log line. It has no push, pull-request or schedule trigger.
