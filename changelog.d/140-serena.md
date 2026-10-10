### Added

- **`.serena/project.yml` is tracked** (#140): the shared Serena project file (`project_name: "go-enclave"`; language servers go, yaml, bash, markdown). The rest of `.serena/` (caches, memories, `project.local.yml`) stays ignored and refused by the releasability gate, which reports the project file as strip-at-publish like `CLAUDE.md`.
