# Bounded executable bootstrap hashing

The source-schema-v3 bootstrap previously read the entire approved Node executable into one buffer. It now hashes the same opened regular file in chunks of at most 64 KiB, retaining the exact approved version, platform, architecture and executable SHA256. File identity, length and metadata are checked before and after reading; truncation, growth and pathname replacement fail closed. The descriptor always closes.

The one grouped component check fails against the original eager-read guard with an allocation oracle and passes against the replacement. It hashes the actual approved executable and exercises wrong-hash, short-read and replacement refusals. RED and GREEN each joined normally with exits 1 and 0; GREEN has one pass and zero skips. Both independent reviews are preserved alongside the original output. Scoped ESLint and source diff checks passed using the existing repository configuration.

This verifies the bootstrap change only. The full source generator, native derivation and deployed flows were not executed by this check. No measured memory improvement, capacity clearance, native acceptance or launch completion is claimed. Historical sealed source and failed derivation evidence remain unchanged. The 728-row availability ledger is unchanged.
