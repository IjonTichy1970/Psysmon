# Appendices

## Appendix A — Command-line reference

Every flag the daemon accepts, generated from `psysmon --help` so it can never drift from the
build. Command-line options **override** the config file, which overrides the built-in defaults
(see [CLI reference](05-cli-reference.md) for the precedence rule with worked examples).

<!--GEN:cli-->

## Appendix B — Status codes

The full status-code table lives in its own chapter: [Status codes](08-status-codes.md).

## Appendix C — Legacy ↔ modern attribute map

The full legacy-field ↔ modern-attribute mapping table, the side-by-side examples, and the
converter (`psysmon-convert`) usage live in [Configuration → Legacy vs. modern](04-configuration.md).
That chapter is the single source for migration so the mapping never drifts between two copies.
