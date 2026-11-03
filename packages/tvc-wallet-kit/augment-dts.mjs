// Appends to the declarations what src/augmentation.d.ts declares for the
// source: the merge of `PrivateWalletSessionMembers` into helius-wallet-kit's
// root and core `HeliusPrivateWalletSession`. The declaration bundler drops
// that file, so `pnpm build` runs this after tsup.
import { appendFile, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const AUGMENTATION = ["helius-wallet-kit/core", "helius-wallet-kit"]
  .map(
    (name) =>
      `declare module "${name}" {\n  interface HeliusPrivateWalletSession extends PrivateWalletSessionMembers {}\n}\n`,
  )
  .join("");

for (const file of ["dist/index.d.ts", "dist/index.d.cts"]) {
  const path = resolve(import.meta.dirname, file);
  const current = await readFile(path, "utf8");
  if (!current.includes("interface PrivateWalletSessionMembers")) {
    throw new Error(`${file} does not declare PrivateWalletSessionMembers`);
  }
  if (current.includes(AUGMENTATION)) continue;
  await appendFile(path, `\n${AUGMENTATION}`);
}
