import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "tsup";

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url));
const CLIENT_ENTRIES = [
  "dist/react/index.js",
  "dist/react/index.cjs",
];

/**
 * Reapplies the `"use client"` directive to the React entry points.
 *
 * Rollup's treeshaking strips a leading directive from the bundle, and an
 * esbuild banner is treated as the same kind of directive and dropped too.
 * Rewriting the emitted files is the only placement that survives. Without it
 * the Next.js App Router treats these entries as server components and their
 * hooks fail at render.
 */
function restoreClientDirectives(): void {
  for (const file of CLIENT_ENTRIES) {
    const body = readFileSync(file, "utf8");
    if (!body.startsWith('"use client"')) {
      writeFileSync(file, `"use client";\n${body}`);
    }
  }
}

function verifyProductionBoundary(): void {
  const roots = [
    "dist/index.js",
    "dist/protocol.js",
    "dist/browser.js",
    "dist/react/index.js",
    "dist/index.cjs",
    "dist/protocol.cjs",
    "dist/browser.cjs",
    "dist/react/index.cjs",
  ];
  // Names that exist only in the testkit: its session factory and its pinned
  // key fixture.
  const localTestkitMarkers = /LocalTvcSession|local-testkit/;
  const relativeModule = /\.\.?\/[A-Za-z0-9/_-]+\.(?:c?js)/g;
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
    browser: "src/browser.ts",
    testing: "src/testing.ts",
    "react/index": "src/react/index.tsx",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Shared code is hoisted into chunks instead of being copied into each of the
  // four entry points. Shared symbols are reachable from more than one entry,
  // so without this an app importing from two of them ships the client core and
  // the crypto stack twice.
  splitting: true,
  treeshake: true,
  external: ["@heliuslabs/spr", "@solana/kit", "react", "react-dom"],
  onSuccess: async () => {
    restoreClientDirectives();
    verifyProductionBoundary();
  },
});
