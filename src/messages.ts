//@TODO WARNING unchecked claude code

/**
 * Encrypted notes: how a sender tells a recipient what is in a commitment.
 *
 * ECIES, the boring version. A fresh secp256k1 key per message, ECDH with the recipient's view key, sha256 of
 * that as an AES-256-GCM key. The recipient tries to decrypt every `Message` event, the GCM tag failing means
 * "not mine". Nothing onchain says who a message is for, and nothing says who sent it.
 *
 * blob layout:
 *   [0]       version, 1
 *   [1..33)   note tag, all zeros for now, see NO_NOTE_TAG
 *   [33..66)  ephemeral public key, compressed
 *   [66..78)  AES-GCM iv
 *   [78..)    ciphertext of the note as JSON padded to PLAINTEXT_SIZE, 16 byte GCM tag at the end
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
    bytesToBigInt,
    bytesToString,
    concat,
    encodeAbiParameters,
    hexToBytes,
    stringToBytes,
    toBytes,
    toHex,
    type Hex,
    type PublicClient,
} from "viem";
import { CIRCUIT_CONTR_STORAGE_EMPTY, JOIN_SPLIT_SELECTOR } from "./constants.js";
import { hashPublic, keccak31Byte, type CircuitContrStorage } from "./hashing.js";
import { fakeNote, hashNote } from "./proving.js";
import type { Note, PublicHashPreimageInput, WarptoadContract } from "./types.js";

/** secp256k1, `publicKey` is the compressed 33 bytes. Share `toHex(publicKey)` as your address */
export type ViewKey = { privateKey: Uint8Array; publicKey: Uint8Array };

const VERSION = 1;
/** bn254 fields are < 2^254, so this is the longest hex a note field can be */
const MAX_FIELD = (1n << 254n) - 1n;
const NOTE_TAG_SIZE = 32;
const PUB_KEY_SIZE = 33;
const IV_SIZE = 12;
const GCM_TAG_SIZE = 16;
const HEADER_SIZE = 1 + NOTE_TAG_SIZE + PUB_KEY_SIZE + IV_SIZE;

/**
 * TODO note tagging, aztec style. Scanning does one ECDH per message onchain and that is the slow part. The plan:
 * alice and bob do ECDH once with their view keys, `sharedSecret`, and alice tags every note she sends bob with
 *   tag = sha256(sharedSecret, aliceViewPublicKey, chain, txCount)
 * txCount being how many notes she sent bob on that chain so far. Bob keeps a window of the next few tags per
 * contact in a set, and only decrypts messages whose tag is in it. Notes to yourself use
 * sharedSecret = sha256(viewPrivateKey, SELF_DOMAIN).
 *
 * When wiring it up:
 *  - aliceViewPublicKey is in the hash because ECDH is symmetric: without it bob's notes to alice at the same
 *    txCount would get the same tag. chain is in there so counters don't get gaps across chains
 *  - txCount comes from scanning for the last tag that hit, never from local state. A reused count gives two
 *    notes the same tag and links them. Bob's window (aztec uses ~10) covers txs that failed or got reordered
 *  - untagged blobs (first contact, fakes) get a RANDOM tag, not zeros, or "zero tag" = "first contact" leaks.
 *    Right now everything is zero so nothing leaks yet
 *  - on a tagged note the AES key can be sha256(sharedSecret, txCount) instead of ECDH with the ephemeral key,
 *    so bob skips the ECDH entirely and alice can decrypt her own sent notes. Keep the ephemeral key slot filled
 *    with a random key so blobs stay the same shape
 *  - first contact needs alice's view public key inside the JSON so bob can start tagging her. That changes
 *    PLAINTEXT_SIZE, bump VERSION when it happens. The blob header itself doesn't change
 *  - unknown senders still need the full ECDH scan, tagging only speeds up people you know. Aztec avoids that by
 *    requiring senders to be registered first, we keep the full scan as fallback
 */
const NO_NOTE_TAG = new Uint8Array(NOTE_TAG_SIZE);

/** every plaintext is this long, so a ciphertext's length says nothing about the note. It is the JSON of the biggest note */
const PLAINTEXT_SIZE = noteToJson({
    ownerHash: MAX_FIELD,
    sharedNonce: MAX_FIELD,
    assetId: MAX_FIELD,
    amount: MAX_FIELD,
    circuitContrSelector: MAX_FIELD,
    circuitContrStorage: [MAX_FIELD, MAX_FIELD, MAX_FIELD],
}).length;

/** one view key per wallet, from any secret. sha256 mod n has negligible bias since n is within 2^-128 of 2^256 */
export function deriveViewKey(secret: string | Uint8Array): ViewKey {
    const bytes = typeof secret === "string" ? stringToBytes(secret) : secret;
    const scalar = bytesToBigInt(sha256(concat([stringToBytes("WARPTOAD_VIEW_KEY"), bytes]))) % secp256k1.CURVE.n;
    if (scalar === 0n) throw new Error("view key is 0, pick another secret");
    const privateKey = toBytes(scalar, { size: 32 });
    return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) };
}

/** ECDH then sha256, the same on both sides */
async function aesKey(privateKey: Uint8Array, publicKey: Uint8Array) {
    const shared = sha256(secp256k1.getSharedSecret(privateKey, publicKey, true));
    return crypto.subtle.importKey("raw", shared, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptNote(note: Note, recipientViewPublicKey: Uint8Array): Promise<Hex> {
    const ephemeralPrivateKey = secp256k1.utils.randomPrivateKey();
    const ephemeralPublicKey = secp256k1.getPublicKey(ephemeralPrivateKey, true);
    const key = await aesKey(ephemeralPrivateKey, recipientViewPublicKey);
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    // JSON.parse doesn't mind trailing spaces
    const plaintext = noteToJson(note).padEnd(PLAINTEXT_SIZE, " ");
    if (plaintext.length !== PLAINTEXT_SIZE) throw new Error("note doesn't fit, a field is over 2^254?");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, stringToBytes(plaintext));
    return toHex(concat([new Uint8Array([VERSION]), NO_NOTE_TAG, ephemeralPublicKey, iv, new Uint8Array(ciphertext)]));
}

/** null when it is not for this key (or garbage) */
export async function decryptNote(message: Hex, viewPrivateKey: Uint8Array): Promise<Note | null> {
    const bytes = hexToBytes(message);
    if (bytes.length < HEADER_SIZE + GCM_TAG_SIZE || bytes[0] !== VERSION) return null;
    const ephemeralPublicKey = bytes.slice(1 + NOTE_TAG_SIZE, 1 + NOTE_TAG_SIZE + PUB_KEY_SIZE);
    const iv = bytes.slice(HEADER_SIZE - IV_SIZE, HEADER_SIZE);
    try {
        const key = await aesKey(viewPrivateKey, ephemeralPublicKey);
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, bytes.slice(HEADER_SIZE));
        return jsonToNote(bytesToString(new Uint8Array(plaintext)));
    } catch {
        // wrong key: the GCM tag doesn't check out. Or the ephemeral key isn't a point
        return null;
    }
}

/** for a slot nobody receives: a fake note encrypted to a key nobody has, so it looks like any other message */
export async function fakeMessage(nonce: bigint): Promise<Hex> {
    return encryptNote(fakeNote(nonce), secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey(), true));
}

/** keccak31Byte(abi.encode(messages)), the first half of `Warptoad.hashPublic` */
export function hashMessages(messages: Hex[]): bigint {
    return keccak31Byte(encodeAbiParameters([{ type: "bytes[]" }], [messages]));
}

/**
 * mirror of `Warptoad.hashPublic`: the circuit's `public_hash`, goes in the spend signature too.
 * `preimage` is what the circuit gets as `public_hash_preimage`. `other_hash` is 0 until there is something else public
 */
export function publicHashOf(messages: Hex[]): { hash: bigint; preimage: PublicHashPreimageInput } {
    const preimage = { messages_hash: hashMessages(messages), other_hash: 0n };
    return { hash: hashPublic({ messagesHash: preimage.messages_hash, otherHash: preimage.other_hash }), preimage };
}

/**
 * every note encrypted to `viewPrivateKey` in `warptoad`'s Message events, block 0 to now.
 * No caching, one ECDH per message onchain, see NO_NOTE_TAG
 */
export async function getAllNotes(
    warptoad: WarptoadContract,
    publicClient: PublicClient,
    viewPrivateKey: Uint8Array,
): Promise<Note[]> {
    const logs = await publicClient.getContractEvents({
        address: warptoad.address,
        abi: warptoad.abi,
        eventName: "Message",
        fromBlock: 0n,
        toBlock: "latest",
    });
    const notes: Note[] = [];
    for (const log of logs) {
        const note = await decryptNote(log.args.message!, viewPrivateKey);
        // a sender can encrypt something that isn't the leaf, that note is not spendable so it gets dropped
        if (note !== null && hashNote(note) === log.args.commitment) notes.push(note);
    }
    return notes;
}

// ------ note <-> JSON, bigints as hex strings ------

function noteToJson(n: Note): string {
    return JSON.stringify({
        ownerHash: toHex(n.ownerHash),
        sharedNonce: toHex(n.sharedNonce),
        circuitContrSelector: toHex(n.circuitContrSelector ?? JOIN_SPLIT_SELECTOR),
        circuitContrStorage: (n.circuitContrStorage ?? CIRCUIT_CONTR_STORAGE_EMPTY).map(function (x) {
            return toHex(x);
        }),
        assetId: toHex(n.assetId),
        amount: toHex(n.amount),
    });
}

function jsonToNote(json: string): Note {
    const j = JSON.parse(json) as Record<string, string> & { circuitContrStorage: string[] };
    return {
        ownerHash: BigInt(j.ownerHash),
        sharedNonce: BigInt(j.sharedNonce),
        circuitContrSelector: BigInt(j.circuitContrSelector),
        circuitContrStorage: j.circuitContrStorage.map(BigInt) as CircuitContrStorage,
        assetId: BigInt(j.assetId),
        amount: BigInt(j.amount),
    };
}
