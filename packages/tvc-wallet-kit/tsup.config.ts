import { readFileSync, writeFileSync } from "node:fs";
import { defineConfig } from "tsup";

//   @zolana/tvc-wallet-kit       → dist/index.js       (HeliusPrivateWalletProvider, hooks)
//   @zolana/tvc-wallet-kit/next  → dist/next/index.js  (the tvc-gateway, indexer and prover route handler)
export default defineConfig({
  entry: {
    index: "src/index.ts",
    "next/index": "src/next/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  // Treeshaking drops the leading "use client"; without it the Next.js App
  // Router renders the provider as a server component.
  async onSuccess() {
    for (const file of ["dist/index.js", "dist/index.cjs"]) {
      const body = readFileSync(file, "utf8");
      if (!body.startsWith('"use client"')) writeFileSync(file, `"use client";\n${body}`);
    }
  },
});
