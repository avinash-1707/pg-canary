# CI artifacts

`internal/ci` converts the redacted report contract into GitHub workflow
annotations and SARIF 2.1.0. Consumers should generate artifacts only from the
serialized report, never from raw connection or fixture input.
