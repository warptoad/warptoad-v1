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
import { FAKE_COMMITMENT_DOMAIN, FAKE_NULLIFIER_DOMAIN } from "./constants.js";

/** ascii "GIGA_LEAF", right-aligned in 32 bytes (defined in hashing.nr, not constants.nr) */
export const GIGA_LEAF_DOMAIN =
    0x0000000000000000000000000000000000000000000000474947415f4c454146n;

export type PubKey = { x: bigint; y: bigint };

/** `[Field; CIRCUIT_CONTR_STORAGE_SIZE]` */
export type CircuitContrStorage = [bigint, bigint, bigint];
/** `[Field; CIRCUIT_CONTR_AUTH_SIZE]` */
export type CircuitContrAuthSigInputs = [bigint, bigint, bigint, bigint, bigint, bigint];
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

/** `hash_circuit_contract_storage`: Poseidon2(circuit_contr_storage) over CIRCUIT_CONTR_STORAGE_SIZE fields */
export function hashCircuitContractStorage({
    circuitContrStorage,
}: {
    circuitContrStorage: CircuitContrStorage;
}): bigint {
    return poseidon2Hash(circuitContrStorage);
}

/** `hash_circuit_contract_auth_sig`: Poseidon2(auth_sig_inputs) over CIRCUIT_CONTR_AUTH_SIZE fields */
export function hashCircuitContractAuthSig({
    authSigInputs,
}: {
    authSigInputs: CircuitContrAuthSigInputs;
}): bigint {
    return poseidon2Hash(authSigInputs);
}

/** `hash_pre_commitment`: Poseidon2([owner_hash, shared_nonce, circuit_contr_selector, circuit_contr_storage_hash]) */
export function hashPreCommitment({
    ownerHash,
    sharedNonce,
    circuitContrSelector,
    circuitContrStorageHash,
}: {
    ownerHash: bigint;
    sharedNonce: bigint;
    circuitContrSelector: bigint;
    circuitContrStorageHash: bigint;
}): bigint {
    return poseidon2Hash([ownerHash, sharedNonce, circuitContrSelector, circuitContrStorageHash]);
}

/** `hash_owner`: Poseidon2([spend_pub_key.x, spend_pub_key.y, dest_giga_index, nullifier_secret]) */
export function hashOwner({
    spendPubKey,
    destGigaIndex,
    nullifierSecret,
}: {
    spendPubKey: PubKey;
    destGigaIndex: bigint;
    nullifierSecret: bigint;
}): bigint {
    return poseidon2Hash([spendPubKey.x, spendPubKey.y, destGigaIndex, nullifierSecret]);
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
