"""The psysmon control/query channel (#69): an opt-in, loopback-default, token-gated
JSON-over-(optional-)TLS service for querying status and performing runtime actions
(ack/note/reload). A modern, security-first replacement for sysmon 0.93's cleartext tcp/1345
protocol — see ``docs/`` and issue #69 for the security model."""
