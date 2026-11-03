import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    // @turnkey/react-wallet-kit's ESM build imports without file extensions,
    // which Node refuses; vite resolves them like the apps' bundlers do.
    server: { deps: { inline: ["helius-wallet-kit", "@turnkey/react-wallet-kit"] } },
  },
});
