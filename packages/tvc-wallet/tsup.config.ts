import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "tsup";

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url));

function verifyProductionBoundary(): void {
  const roots = ["dist/index.js", "dist/protocol.js", "dist/decryption-service.js"];
  // Names that exist only in the testkit: its session factory and its pinned
  // key fixture.
  const localTestkitMarkers = /LocalTvcSession|local-testkit/;
  const relativeModule = /\.\.?\/[A-Za-z0-9/_-]+\.js/g;
  const visited = new Set<string>();

  const inspect = (path: string): void => {
    const file = resolve(PACKAGE_ROOT, path);
    if (visited.has(file)) return;
    visited.add(file);
    const source = readFileSync(file, "utf8");
    if (localTestkitMarkers.test(source)) {
      throw new Error(`local testkit code is reachable from a production entry: ${path}`);
    }
    for (const specifier of source.match(relativeModule) ?? []) {
      inspect(resolve(dirname(file), specifier));
    }
  };

  for (const root of roots) inspect(root);
}

export default defineConfig({
  entry: {
    index: "src/index.ts",
    protocol: "src/protocol.ts",
    "decryption-service": "src/decryption-service.ts",
    testing: "src/testing.ts",
  },
  // ESM only: `@heliuslabs/spr`, which the client imports, ships no CommonJS.
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Shared code is hoisted into chunks instead of being copied into each of the
  // entry points. Shared symbols are reachable from more than one entry,
  // so without this an app importing from two of them ships the client core and
  // the crypto stack twice.
  splitting: true,
  treeshake: true,
  external: ["@heliuslabs/spr", "@solana/kit"],
  onSuccess: async () => {
    verifyProductionBoundary();
  },
});
