import {
  SHIELDED_POOL_PROGRAM_ID,
  SOL_MINT,
  SPL_TOKEN_PROGRAM_ID,
} from "@heliuslabs/zolana";
import { getAssociatedTokenAddress } from "@heliuslabs/zolana/addresses";
import { decodeSplAssetRegistry } from "@heliuslabs/zolana/interface";
import { address } from "@solana/kit";
import { Connection, PublicKey } from "@solana/web3.js";

/** An asset the shielded pool accepts, keyed by its mint like the SDK wallet's balances. */
export type WalletAsset = Readonly<{
  mint: string;
  decimals: number;
  name: string;
  symbol: string;
}>;

export const SOL_ASSET: WalletAsset = Object.freeze<WalletAsset>({
  mint: SOL_MINT,
  decimals: 9,
  name: "Solana",
  symbol: "SOL",
});

const TOKEN_METADATA_PROGRAM = new PublicKey(
  "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
);
const METADATA_SEED = new TextEncoder().encode("metadata");

type AssetMetadata = Readonly<{ name?: string; symbol?: string }>;

function cleanMetadataText(value: string, maximum: number): string | undefined {
  const cleaned = value.replaceAll("\0", "").trim().slice(0, maximum);
  return cleaned.length === 0 ? undefined : cleaned;
}

function decodeMetadataText(data: Uint8Array): AssetMetadata {
  let offset = 65; // key + update authority + mint
  const readString = (maximum: number): string | undefined => {
    if (offset + 4 > data.byteLength) return undefined;
    const length = new DataView(
      data.buffer,
      data.byteOffset + offset,
      4,
    ).getUint32(0, true);
    offset += 4;
    if (length > 1_024 || offset + length > data.byteLength) return undefined;
    const value = cleanMetadataText(
      new TextDecoder("utf-8", { fatal: true }).decode(
        data.subarray(offset, offset + length),
      ),
      maximum,
    );
    offset += length;
    return value;
  };
  try {
    return { name: readString(64), symbol: readString(16) };
  } catch {
    return {};
  }
}

function metadataAddress(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [METADATA_SEED, TOKEN_METADATA_PROGRAM.toBytes(), mint.toBytes()],
    TOKEN_METADATA_PROGRAM,
  )[0];
}

/**
 * A placeholder for a mint the wallet holds but the registry scan has not
 * described yet; the next asset refresh replaces it.
 */
export function unknownAsset(mint: string): WalletAsset {
  return Object.freeze<WalletAsset>({ mint, decimals: 0, name: "", symbol: "SPL" });
}

function walletAsset(mint: string, decimals: number, metadata: AssetMetadata): WalletAsset {
  return Object.freeze<WalletAsset>({
    mint,
    decimals,
    name: metadata.name ?? "",
    symbol: metadata.symbol ?? "SPL",
  });
}

export function assetLabel(asset: WalletAsset): string {
  if (asset.mint === SOL_MINT) return "SOL — Solana";
  const identity =
    asset.name.length === 0 || asset.name === asset.symbol
      ? asset.symbol
      : `${asset.symbol} — ${asset.name}`;
  return `${identity} · ${asset.mint}`;
}

export function formatAssetAmount(
  value: string | number | bigint,
  asset: WalletAsset,
): string {
  const raw = BigInt(value);
  const base = 10n ** BigInt(asset.decimals);
  const whole = raw / base;
  const fraction = (raw % base)
    .toString()
    .padStart(asset.decimals, "0")
    .replace(/0+$/, "");
  return `${whole}${fraction ? `.${fraction}` : ""} ${asset.symbol}`;
}

export function parseAssetAmount(value: string, asset: WalletAsset): bigint {
  const normalized = value.trim();
  const pattern = new RegExp(
    asset.decimals === 0
      ? "^(?:0|[1-9][0-9]*)$"
      : `^(?:0|[1-9][0-9]*)(?:\\.[0-9]{1,${String(asset.decimals)}})?$`,
  );
  if (!pattern.test(normalized)) throw new Error(`Enter a valid ${asset.symbol} amount`);
  const [whole = "0", fraction = ""] = normalized.split(".");
  const raw =
    BigInt(whole) * 10n ** BigInt(asset.decimals) +
    BigInt(fraction.padEnd(asset.decimals, "0"));
  if (raw <= 0n) throw new Error(`Enter a positive ${asset.symbol} amount`);
  return raw;
}

/** Classic SPL mints registered by the shielded pool, plus native SOL. */
export async function fetchWalletAssets(
  connection: Connection,
): Promise<readonly WalletAsset[]> {
  const records = await connection.getProgramAccounts(
    new PublicKey(SHIELDED_POOL_PROGRAM_ID),
    { commitment: "confirmed", filters: [{ dataSize: 48 }] },
  );
  const registries = records.flatMap(({ account }) => {
    try {
      return [decodeSplAssetRegistry(account.data)];
    } catch {
      return [];
    }
  });
  const mintKeys = registries.map(({ mint }) => new PublicKey(mint));
  const assetAccounts =
    mintKeys.length === 0
      ? []
      : await connection.getMultipleAccountsInfo(
          [...mintKeys, ...mintKeys.map(metadataAddress)],
          "confirmed",
        );
  const mintAccounts = assetAccounts.slice(0, mintKeys.length);
  const metadataAccounts = assetAccounts.slice(mintKeys.length);
  const tokenProgram = new PublicKey(SPL_TOKEN_PROGRAM_ID);
  const assets = registries.map((registry, index) => {
    const mintAccount = mintAccounts[index];
    // The classic SPL Mint layout stores decimals at byte 44. Reading all mint
    // accounts together avoids two RPC round trips per registered asset.
    if (
      !mintAccount?.owner.equals(tokenProgram) ||
      mintAccount.data.byteLength <= 44
    ) {
      return null;
    }
    return walletAsset(
      registry.mint,
      mintAccount.data[44]!,
      metadataAccounts[index]?.owner.equals(TOKEN_METADATA_PROGRAM)
        ? decodeMetadataText(metadataAccounts[index]!.data)
        : {},
    );
  });
  return Object.freeze([
    SOL_ASSET,
    ...assets
      .filter((asset): asset is WalletAsset => asset !== null)
      .sort((left, right) => left.mint.localeCompare(right.mint)),
  ]);
}

export async function fetchPublicAssetBalances(
  connection: Connection,
  owner: string,
  assets: readonly WalletAsset[],
): Promise<readonly bigint[]> {
  const splAssets = assets.filter((asset) => asset.mint !== SOL_MINT);
  const associatedTokenAccounts = await Promise.all(
    splAssets.map((asset) =>
      getAssociatedTokenAddress(
        address(owner),
        address(asset.mint),
        address(SPL_TOKEN_PROGRAM_ID),
      ),
    ),
  );
  const [nativeBalance, tokenAccounts] = await Promise.all([
    connection.getBalance(new PublicKey(owner), "confirmed"),
    associatedTokenAccounts.length === 0
      ? Promise.resolve([])
      : connection.getMultipleAccountsInfo(
          associatedTokenAccounts.map((tokenAccount) => new PublicKey(tokenAccount)),
          "confirmed",
        ),
  ]);
  let splIndex = 0;
  return assets.map((asset) => {
    if (asset.mint === SOL_MINT) return BigInt(nativeBalance);
    const account = tokenAccounts[splIndex++];
    if (
      !account?.owner.equals(new PublicKey(SPL_TOKEN_PROGRAM_ID)) ||
      account.data.byteLength < 72
    ) {
      return 0n;
    }
    return new DataView(
      account.data.buffer,
      account.data.byteOffset,
      account.data.byteLength,
    ).getBigUint64(64, true);
  });
}
