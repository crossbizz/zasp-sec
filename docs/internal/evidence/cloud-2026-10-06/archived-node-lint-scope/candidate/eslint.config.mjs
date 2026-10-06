import { defineConfig, globalIgnores } from "eslint/config";
import eslint from "@eslint/js";
import next from "@next/eslint-plugin-next";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

import noRawFetchRule from "./eslint-rules/no-raw-fetch.mjs";

const eslintConfig = defineConfig([
  globalIgnores([
    ".superpowers/**",
    "superpowers/sdd/**",
    "docs/internal/archive/**",
    "services/platform/migrations/tools/ordered-current-private-historical-v1/**",
    ".next/**",
    "dist/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  react.configs.flat.recommended,
  react.configs.flat["jsx-runtime"],
  reactHooks.configs.flat["recommended-latest"],
  jsxA11y.flatConfigs.recommended,
  next.configs["core-web-vitals"],
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.serviceworker,
      },
    },
    settings: {
      react: {
        version: "detect",
      },
    },
  },
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", ignoreRestSiblings: true }],
    },
  },
  {
    files: [
      "scripts/**/*.mjs",
      "services/platform/migrations/tools/**/*.mjs",
      // Fixed immutable copies of the Node diagnostics retain all other rules.
      "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.mjs",
      "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.test.mjs",
    ],
    rules: {
      // These are Node tools, not Next.js modules.
      "@next/next/no-assign-module-variable": "off",
    },
  },
  {
    files: [
      // These fixed validators deliberately reject control bytes; ordinary
      // product scripts retain the rule (verified by eslint-scope.test.mjs).
      "apps/web/api/security-agent-trigger-rules.ts",
      "scripts/discovery-current-composition.mjs",
      "services/platform/migrations/tools/build-ordered-current-integrity.mjs",
      "services/platform/migrations/tools/build-worker-readiness-graph.mjs",
      "services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.mjs",
      "services/platform/migrations/tools/worker-readiness-regions.mjs",
    ],
    rules: { "no-control-regex": "off" },
  },
  {
    files: [
      "app/**/*.{js,jsx,ts,tsx,mjs,cjs}",
      "apps/web/**/*.{js,jsx,ts,tsx,mjs,cjs}",
    ],
    ignores: ["apps/web/api/client.ts", "apps/web/api/generated.ts"],
    plugins: {
      zasp: {
        rules: {
          "no-raw-fetch": noRawFetchRule,
        },
      },
    },
    rules: {
      "zasp/no-raw-fetch": "error",
    },
  },
]);

export default eslintConfig;
