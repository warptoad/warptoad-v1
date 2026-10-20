/**
 * TypeScript mirror of `circuits/src/hashing.nr`.
 *
 * Every function takes a single named-argument object so call sites can't
 * silently swap two `bigint`s.
 *
 * `@zkpassport/poseidon2` is the same Poseidon2 instance as noir-lang/poseidon
 * (bn254, t=4). Verified against `Poseidon2::hash` for input sizes 2/3/4/6/9.
 */
import { poseidon2Hash } from "@zkpassport/poseidon2";
import { keccak256, type Hex } from "viem";
import { FAKE_COMMITMENT_DOMAIN, FAKE_NULLIFIER_DOMAIN } from "./constants.js";

/** mirror of `Warptoad.keccak31Byte`: keccak with the last byte dropped, so it fits in a 254 bit field */
export function keccak31Byte(data: Hex): bigint {
    return BigInt(keccak256(data)) >> 8n;
}

/** ascii "GIGA_LEAF", right-aligned in 32 bytes (defined in hashing.nr, not constants.nr) */
export const GIGA_LEAF_DOMAIN =
    0x0000000000000000000000000000000000000000000000474947415f4c454146n;

export type PubKey = { x: bigint; y: bigint };

/** `[Field; CIRCUIT_COMP_STORAGE_SIZE]` */
export type CircuitCompStorage = [bigint, bigint, bigint];
/** `[Field; CIRCUIT_COMP_AUTH_SIZE]`, see `authSigInputs` in proving.ts to pad a shorter list */
export type CircuitCompAuthSigInputs = bigint[];
/** `[Field; CIRCUIT_SIZE]` */
export type CircuitSizeFields = [bigint, bigint, bigint, bigint];

/** `hash_giga_leaf`: Poseidon2([local_root, local_edge_index, GIGA_LEAF_DOMAIN]) */
export function hashGigaLeaf({
    localRoot,
    localEdgeIndex,
}: {
    localRoot: bigint;
    localEdgeIndex: bigint;
}): bigint {
    return poseidon2Hash([localRoot, localEdgeIndex, GIGA_LEAF_DOMAIN]);
}

/** `hash_commitment`: Poseidon2([pre_commitment_hash, asset_id, amount]) */
export function hashCommitment({
    preCommitmentHash,
    assetId,
    amount,
}: {
    preCommitmentHash: bigint;
    assetId: bigint;
    amount: bigint;
}): bigint {
    return poseidon2Hash([preCommitmentHash, assetId, amount]);
}

/** `hash_circuit_component_storage`: Poseidon2(circuit_comp_storage) over CIRCUIT_COMP_STORAGE_SIZE fields */
export function hashCircuitComponentStorage({
    circuitCompStorage,
}: {
    circuitCompStorage: CircuitCompStorage;
}): bigint {
    return poseidon2Hash(circuitCompStorage);
}

/** `hash_circuit_component_auth_sig`: Poseidon2(auth_sig_inputs) over CIRCUIT_COMP_AUTH_SIZE fields */
export function hashCircuitComponentAuthSig({
    authSigInputs,
}: {
    authSigInputs: CircuitCompAuthSigInputs;
}): bigint {
    return poseidon2Hash(authSigInputs);
}

/** `hash_pre_commitment`: Poseidon2([owner_hash, shared_nonce, circuit_comp_selector, circuit_comp_storage_hash]) */
export function hashPreCommitment({
    ownerHash,
    sharedNonce,
    circuitCompSelector,
    circuitCompStorageHash,
}: {
    ownerHash: bigint;
    sharedNonce: bigint;
    circuitCompSelector: bigint;
    circuitCompStorageHash: bigint;
}): bigint {
    return poseidon2Hash([ownerHash, sharedNonce, circuitCompSelector, circuitCompStorageHash]);
}

/**
 * `hash_owner_keys`: Poseidon2([spend_pub_key.x, spend_pub_key.y, nullifier_secret])
 *
 * The chain independent half of an owner hash. Telling someone this reveals which giga index every
 * owner hash of yours is on, so only share it when that is fine (a swaptoad maker gives it to the taker)
 */
export function hashOwnerKeys({ spendPubKey, nullifierSecret }: { spendPubKey: PubKey; nullifierSecret: bigint }): bigint {
    return poseidon2Hash([spendPubKey.x, spendPubKey.y, nullifierSecret]);
}

/** `hash_owner`: Poseidon2([owner_keys_hash, giga_index]), the giga index of the chain the owner spends on */
export function hashOwner({ ownerKeysHash, gigaIndex }: { ownerKeysHash: bigint; gigaIndex: bigint }): bigint {
    return poseidon2Hash([ownerKeysHash, gigaIndex]);
}

/**
 * `hash_shared_nonce_swaptoad`: Poseidon2([shared_nullifier_secret, commitment_type])
 *
 * On a fill the taker builds the maker's two notes, so their nonces are derived from the lock's shared secret:
 * type 0 is the note the maker gets paid in, type 1 is the maker's change
 */
export function hashSharedNonceSwaptoad({
    sharedNullifierSecret,
    commitmentType,
}: {
    sharedNullifierSecret: bigint;
    commitmentType: bigint;
}): bigint {
    return poseidon2Hash([sharedNullifierSecret, commitmentType]);
}

/**
 * `hash_spend_signature_inputs`:
 * Poseidon2([...spend_commitment_hashes, ...recipient_commitment_hashes, public_hash])
 * over CIRCUIT_SIZE * 2 + 1 fields.
 *
 * The circuit reads `spend_commitments[i].commitment_hash` from `ProvenCommitment`;
 * pass those hashes directly here. Unused slots must be the same fake
 * commitment hashes the circuit uses, not zero.
 */
export function hashSpendSignatureInputs({
    publicHash,
    spendCommitmentHashes,
    recipientCommitmentHashes,
}: {
    publicHash: bigint;
    spendCommitmentHashes: CircuitSizeFields;
    recipientCommitmentHashes: CircuitSizeFields;
}): bigint {
    return poseidon2Hash([...spendCommitmentHashes, ...recipientCommitmentHashes, publicHash]);
}

/**
 * `hash_public`: Poseidon2([messages_hash, other_hash]), the sdk's convention for the circuit's `public_hash`.
 * The contract passes `publicHash` through to the proof unchecked, only `first_message_hash` is computed onchain,
 * so what goes in here is up to the signer. `messagesHash` is `hashMessages` in messages.ts, `otherHash` is 0 for now
 */
export function hashPublic({ messagesHash, otherHash }: { messagesHash: bigint; otherHash: bigint }): bigint {
    return poseidon2Hash([messagesHash, otherHash]);
}

/**
 * `hash_asset_id`: Poseidon2([first_giga_index, last_giga_index, wrapper_id]), mirrored in `Warptoad.shield`.
 * The range is the giga leaves the wrapper factory trusts, `wrapperId` is keccak31Byte(factory, wrapperAssetHash),
 * see assets.ts. Spending a note needs this preimage, not just the hash
 */
export function hashAssetId({
    firstGigaIndex,
    lastGigaIndex,
    wrapperId,
}: {
    firstGigaIndex: bigint;
    lastGigaIndex: bigint;
    wrapperId: bigint;
}): bigint {
    return poseidon2Hash([firstGigaIndex, lastGigaIndex, wrapperId]);
}

/** `hash_nullifier`: Poseidon2([nullifier_secret, giga_leaf_index, local_leaf_index]) */
export function hashNullifier({
    nullifierSecret,
    gigaLeafIndex,
    localLeafIndex,
}: {
    nullifierSecret: bigint;
    gigaLeafIndex: bigint;
    localLeafIndex: bigint;
}): bigint {
    return poseidon2Hash([nullifierSecret, gigaLeafIndex, localLeafIndex]);
}

/**
 * `hash_fake_nullifier`: Poseidon2([nonce, FAKE_NULLIFIER_DOMAIN])
 *
 * 2 inputs on purpose: real nullifiers have 3, so a fake one can never collide
 * with a real one. Do not "fix" this to 3.
 */
export function hashFakeNullifier({ nonce }: { nonce: bigint }): bigint {
    return poseidon2Hash([nonce, FAKE_NULLIFIER_DOMAIN]);
}

/**
 * `hash_fake_commitment`: Poseidon2([nonce, FAKE_COMMITMENT_DOMAIN])
 *
 * 2 inputs on purpose: real commitments have 3, and FAKE_COMMITMENT_DOMAIN sits
 * where asset_id would be, which is never a valid asset_id.
 */
export function hashFakeCommitment({ nonce }: { nonce: bigint }): bigint {
    return poseidon2Hash([nonce, FAKE_COMMITMENT_DOMAIN]);
}
