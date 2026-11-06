import type {
  AuthorizeTvcRequestInput,
  TvcOperationAuthorizer,
} from "../client/operation-executor.js";
import { clientKeyIdFor } from "../protocol/digest.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { authorizedRequestMessage, compactLowS } from "./authorizer.js";

const DATABASE_NAME = "zolana-tvc-privacy-wallet-authorizer-v1";
const STORE_NAME = "records";
const KEY_RECORD = "client-auth-p256";
function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

type StoredClientKey = {
  version: 1;
  clientKeyId: string;
  clientPublicKey: string;
  privateKey: CryptoKey;
  storageKey: CryptoKey;
};

type PersistentBrowserTvcSealedValue = {
  readonly version: 1;
  readonly nonce: string;
  readonly ciphertext: string;
};

export type PersistentBrowserTvcAuthorizer = {
  /** Stable public registration data used by descriptor provisioning. */
  readonly clientKeyId: string;
  readonly clientPublicKey: string;
  /** Closed-operation authorizer; it never exposes the private CryptoKey. */
  readonly authorizer: TvcOperationAuthorizer;
  /** Encrypts privacy material under a non-exportable, device-local AES key. */
  seal(plaintext: Uint8Array, additionalData: Uint8Array): Promise<PersistentBrowserTvcSealedValue>;
  /** Opens a value sealed by this browser profile. */
  open(sealed: PersistentBrowserTvcSealedValue, additionalData: Uint8Array): Promise<Uint8Array>;
};

export type PersistentBrowserTvcAuthorizerOptions = {
  /** Selects an isolated persistent-key namespace for a demo or tenant. */
  readonly databaseName?: string;
};

function openDatabase(name: string): Promise<IDBDatabase> {
  if (!globalThis.indexedDB) throw new TvcError("UnsupportedPlatform");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onblocked = () => reject(new TvcError("StorageUnavailable"));
    request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
    request.onsuccess = () => resolve(request.result);
  });
}

function readRecord(database: IDBDatabase): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(KEY_RECORD);
    request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
    request.onsuccess = () => resolve(request.result);
  });
}

/**
 * Commits `created` only if the store is still empty, and returns whichever
 * record wins, inside one readwrite transaction. A read-then-write across two
 * transactions would let two tabs each generate a key and silently discard the
 * loser's, leaving that tab signing with a key no longer in storage.
 */
function createIfAbsent(
  database: IDBDatabase,
  created: StoredClientKey,
): Promise<StoredClientKey> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const read = store.get(KEY_RECORD);
    let record: StoredClientKey | null = null;
    read.onerror = () => reject(read.error ?? new TvcError("StorageUnavailable"));
    read.onsuccess = () => {
      try {
        record = read.result ? parseRecord(read.result) : created;
        if (!read.result) store.put(created, KEY_RECORD);
      } catch (error) {
        transaction.abort();
        reject(error);
      }
    };
    transaction.onerror = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
    transaction.onabort = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
    transaction.oncomplete = () =>
      record ? resolve(record) : reject(new TvcError("StorageUnavailable"));
  });
}

async function loadOrCreateRecord(database: IDBDatabase): Promise<StoredClientKey> {
  const stored = await readRecord(database);
  if (stored) return parseRecord(stored);
  return createIfAbsent(database, await createRecord());
}

function parseRecord(value: unknown): StoredClientKey {
  if (!value || typeof value !== "object") throw new TvcError("StorageCorrupted");
  const record = value as Partial<StoredClientKey>;
  if (
    record.version !== 1 ||
    typeof record.clientKeyId !== "string" ||
    typeof record.clientPublicKey !== "string" ||
    !(record.privateKey instanceof CryptoKey) ||
    !(record.storageKey instanceof CryptoKey) ||
    record.privateKey.type !== "private" ||
    record.privateKey.extractable ||
    !record.privateKey.usages.includes("sign") ||
    record.privateKey.algorithm.name !== "ECDSA" ||
    (record.privateKey.algorithm as EcKeyAlgorithm).namedCurve !== "P-256" ||
    record.storageKey.type !== "secret" ||
    record.storageKey.extractable ||
    record.storageKey.algorithm.name !== "AES-GCM" ||
    !record.storageKey.usages.includes("encrypt") ||
    !record.storageKey.usages.includes("decrypt")
  ) {
    throw new TvcError("StorageCorrupted");
  }
  const publicKey = decodeLowerHex(record.clientPublicKey);
  if (
    publicKey.length !== 65 ||
    publicKey[0] !== 4 ||
    record.clientKeyId !== clientKeyIdFor(publicKey)
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return record as StoredClientKey;
}

async function createRecord(): Promise<StoredClientKey> {
  if (!globalThis.crypto?.subtle) throw new TvcError("UnsupportedPlatform");
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  if (pair.privateKey.extractable) throw new TvcError("KeyNotNonExportable");
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  if (publicKey.length !== 65 || publicKey[0] !== 4) {
    throw new TvcError("InvalidPublicKey");
  }
  const storageKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return {
    version: 1,
    clientKeyId: clientKeyIdFor(publicKey),
    clientPublicKey: encodeLowerHex(publicKey),
    privateKey: pair.privateKey,
    storageKey,
  };
}

function parseSealedValue(value: PersistentBrowserTvcSealedValue): {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (value.version !== 1) {
    throw new TvcError("StorageCorrupted");
  }
  try {
    const nonce = decodeLowerHex(value.nonce);
    const ciphertext = decodeLowerHex(value.ciphertext);
    if (nonce.length !== 12 || ciphertext.length < 16) {
      throw new TvcError("StorageCorrupted");
    }
    return { nonce, ciphertext };
  } catch {
    throw new TvcError("StorageCorrupted");
  }
}

async function assertKeyMatches(record: StoredClientKey): Promise<void> {
  const message = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    record.privateKey,
    message,
  );
  const publicKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(decodeLowerHex(record.clientPublicKey)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  if (
    !(await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      message,
    ))
  ) {
    throw new TvcError("StorageCorrupted");
  }
}

/**
 * Loads or creates the browser's dedicated TVC authorization key. This key is
 * separate from Turnkey's persistent login/session key and cannot be exported.
 */
export async function loadOrCreatePersistentBrowserTvcAuthorizer(
  options: PersistentBrowserTvcAuthorizerOptions = {},
): Promise<PersistentBrowserTvcAuthorizer> {
  const database = await openDatabase(options.databaseName ?? DATABASE_NAME);
  try {
    const record = await loadOrCreateRecord(database);
    await assertKeyMatches(record);
    return {
      clientKeyId: record.clientKeyId,
      clientPublicKey: record.clientPublicKey,
      authorizer: {
        clientKeyId: record.clientKeyId,
        async authorizeTvcRequest(input: AuthorizeTvcRequestInput) {
          const expected = authorizedRequestMessage(input, record.clientKeyId);
          return compactLowS(
            await crypto.subtle.sign(
              { name: "ECDSA", hash: "SHA-256" },
              record.privateKey,
              ownedBytes(expected),
            ),
          );
        },
      },
      async seal(plaintext, additionalData) {
        if (plaintext.length === 0 || additionalData.length === 0) {
          throw new TvcError("StorageCorrupted");
        }
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const plaintextBytes = ownedBytes(plaintext);
        const additionalDataBytes = ownedBytes(additionalData);
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: nonce,
              additionalData: additionalDataBytes,
              tagLength: 128,
            },
            record.storageKey,
            plaintextBytes,
          ),
        );
        return Object.freeze({
          version: 1 as const,
          nonce: encodeLowerHex(nonce),
          ciphertext: encodeLowerHex(ciphertext),
        });
      },
      async open(sealed, additionalData) {
        if (additionalData.length === 0) throw new TvcError("StorageCorrupted");
        const parsed = parseSealedValue(sealed);
        const nonce = ownedBytes(parsed.nonce);
        const ciphertext = ownedBytes(parsed.ciphertext);
        const additionalDataBytes = ownedBytes(additionalData);
        try {
          return new Uint8Array(
            await crypto.subtle.decrypt(
              {
                name: "AES-GCM",
                iv: nonce,
                additionalData: additionalDataBytes,
                tagLength: 128,
              },
              record.storageKey,
              ciphertext,
            ),
          );
        } catch {
          throw new TvcError("StorageCorrupted");
        }
      },
    };
  } finally {
    database.close();
  }
}
