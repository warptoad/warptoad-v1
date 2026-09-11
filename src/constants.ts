/**
 * TypeScript mirror of `circuits/src/constants.nr`. Keep in sync by hand.
 */
import { poseidon2Hash } from "@zkpassport/poseidon2";

// asset_id, amount, expiry, ref_to_lock: 4 inputs needed, poseidon2 cost is the
// same up to 6, so 6.
export const CIRCUIT_CONTR_AUTH_SIZE = 6;
export const CIRCUIT_CONTR_STORAGE_SIZE = 3;
export const CIRCUIT_CONTR_STORAGE_EMPTY: readonly bigint[] = Object.freeze(
    new Array<bigint>(CIRCUIT_CONTR_STORAGE_SIZE).fill(0n),
);
export const CIRCUIT_CONTR_STORAGE_EMPTY_HASH: bigint = poseidon2Hash([
    ...CIRCUIT_CONTR_STORAGE_EMPTY,
]);
export const CIRCUIT_SIZE = 4;
// to match aztec note_hash_tree, also we need to put edge index at 2**40 - 1 there
// no tree resets: at ~12M leaves/day 2^40 lasts ~250 years, quantum breaks bn254 first
export const MAX_TREE_DEPTH = 40;

/** ascii "JOIN_SPLIT", right-aligned in 32 bytes */
export const JOIN_SPLIT_SELECTOR =
    0x000000000000000000000000000000000000000000004a4f494e5f53504c4954n;

export const JOIN_SPLIT_NULLIFIER_SLOT = 0x00n;
export const SWAP_NULLIFIER_SLOT = 0x00n;
export const SWAP_TIMER_NULLIFIER_SLOT = 0x01n;

/** ascii "FAKE_NULLIFIER", right-aligned in 32 bytes */
export const FAKE_NULLIFIER_DOMAIN =
    0x00000000000000000000000000000000000046414b455f4e554c4c4946494552n;
/** ascii "FAKE_COMMITMENT", right-aligned in 32 bytes */
export const FAKE_COMMITMENT_DOMAIN =
    0x000000000000000000000000000000000046414b455f434f4d4d49544d454e54n;
