import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

const TURNKEY_PROOF_SEAM =
  "packages/tvc-wallet/src/verify/internal/turnkey-proof-seam.ts";

export default [
  {
    ignores: ["**/dist/**", "**/node_modules/**"],
  },
  js.configs.recommended,
  {
    files: [
      "packages/tvc-wallet/**/*.{ts,tsx}",
      "packages/tvc-wallet-kit/**/*.{ts,tsx}",
      "examples/privacy-wallet-next-app/src/**/*.{ts,tsx}",
      "examples/typescript-client/{src,examples}/**/*.{ts,tsx}",
      "apps/tvc-gateway/e2e/*.ts",
    ],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "no-undef": "off",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@turnkey/*", "@turnkey/*/**"],
              message:
                "@turnkey/* imports are only allowed in the TVC Turnkey proof seam.",
            },
          ],
        },
      ],
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    files: [TURNKEY_PROOF_SEAM],
    rules: {
      "no-restricted-imports": "off",
    },
  },
  {
    // The client example signs Solana transactions with the wallet's own
    // Turnkey API key; the restriction above guards the package's proof seam.
    files: ["examples/typescript-client/src/lib.ts"],
    rules: {
      "no-restricted-imports": "off",
    },
  },
];
