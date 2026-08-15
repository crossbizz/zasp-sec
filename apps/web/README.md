# Web package boundary

This package is the deployable ownership boundary for Zasp's web application.
Its build script delegates to the existing locked repository-root Vinext/React
production build. It does not copy the UI, introduce a second dependency graph,
or create another lockfile.

Run the exact boundary from the repository root:

```bash
npm --prefix apps/web run build
```
