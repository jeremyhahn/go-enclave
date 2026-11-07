### Changed

- Every CI, release and batch job, the CI Gate included, runs on GitHub-hosted `ubuntu-latest` runners; only the code review keeps its own runners. A hosted runner carries no `GOPROXY`, so the toolchain image build uses the Dockerfile's default public Go module proxy, which serves the now public root module, and each job that builds an image first frees disk on the runner (#293). Nothing changes for Go callers.
