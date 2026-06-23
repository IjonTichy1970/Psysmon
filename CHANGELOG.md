# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold: package layout, packaging (`pyproject.toml`), CI, and the
  monitoring-engine architecture (config parser, async scheduler, checks, notifier, output).
- README describing the rewrite, its dependency-aware monitoring model, and how it differs
  from the original C `sysmon`.
- Status-code definitions and display mappings ported from the original `lib.c`.
- Core data model (`Node`, `NodeState`) ported from the original `struct hostinfo`.

[Unreleased]: https://github.com/IjonTichy1970/Sysmon/commits/main
