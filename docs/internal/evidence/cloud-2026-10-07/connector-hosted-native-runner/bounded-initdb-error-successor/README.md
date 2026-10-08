# Bounded pre-credential initdb error diagnostic

The actual raw original-image PostgreSQL version probe exits zero with the exact full version, while initdb still exits one. The host-loader mismatch hypothesis is unsupported. The successor prints only the pinned tool's first four initdb-prefixed stderr lines, each capped at 512 characters, before any FGA/API credential generation. Owned-runtime paths and explicit proxy environment values are masked before truncation; percent/newline controls are escaped. The helper refuses if a token has already been generated. No provider/API output or raw archive is published.

Independent source review passes. Original initdb flags, source/image/version pins, nine subcases, command captures, floors and cleanup remain unchanged. The next hosted error observation is required before a compatibility fix; native and deployment acceptance remain open.
