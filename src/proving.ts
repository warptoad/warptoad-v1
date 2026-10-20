/**
 * Turns wallet state into circuit inputs and circuit inputs into a proof.
 *
 * Nothing in here knows about the happy path or hardhat. It should survive the giga tree unchanged,
 * apart from `spendInput` getting a real giga proof and `pubRoots` real giga values.
 */
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import type { UltraHonkBackend } from "@aztec/bb.js";
import { Trees } from "@warptoad/skinny-fat-imt-js";
import { toHex, type Address, type Hex, type PublicClient } from "viem";
import { CIRCUIT_COMP_AUTH_SIZE, CIRCUIT_COMP_STORAGE_EMPTY, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH } from "./constants.js";
import {
    hashCircuitComponentStorage,
    hashCommitment,
    hashPreCommitment,
    type CircuitCompAuthSigInputs,
    type CircuitCompStorage,
} from "./hashing.js";
import type {
    Asset,
    AuthInputs,
    CircuitInputs,
    CommitmentRecipientDataInput,
    CommitmentSpendProofInput,
    MerkleProofInput,
    Note,
    PubRootsAndIndexesInput,
    UnshieldingCommitmentInput,
} from "./types.js";

/** noir_js only re-exports InputMap, the value type lives in noirc_abi which isn't a direct dependency */
type InputValue = InputMap[string];

// ---------- proving ----------

/** noir_js wants fields as strings, u32 as numbers. Turns every bigint in a nested input into hex */
export function toNoirInputs(value: unknown): InputValue {
    if (typeof value === "bigint") return toHex(value);
    if (typeof value === "number") return value;
    if (Array.isArray(value)) return value.map(toNoirInputs);
    if (typeof value === "object" && value !== null) {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toNoirInputs(v)]));
    }
    throw new Error(`can't convert ${String(value)} to a noir input`);
}

/** witness with noir_js, proof with bb.js. Also returns the public inputs bb saw, to cross check the contract */
export async function prove(
    backend: UltraHonkBackend,
    circuit: CompiledCircuit,
    inputs: CircuitInputs,
): Promise<{ proof: Hex; publicInputs: bigint[] }> {
    const noir = new Noir(circuit);
    const { witness } = await noir.execute(toNoirInputs(inputs) as InputMap);
    const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
    return {
        proof: toHex(proofData.proof),
        publicInputs: proofData.publicInputs.map(function (x) {
            return BigInt(x);
        }),
    };
}

// ---------- trees ----------

/**
 * Local mirror of a contract's commitment tree at `blockNumber` (latest if omitted).
 * Throws if the synced root doesn't match `expectedRoot`, pass the onchain root to be sure
 */
export async function syncedTree(
    contractAddress: Address,
    publicClient: PublicClient,
    treeId: bigint,
    { blockNumber, expectedRoot }: { blockNumber?: bigint; expectedRoot?: bigint } = {},
) {
    const trees = new Trees(contractAddress, publicClient);
    const synced = await trees.sync([treeId], { blockNumber: blockNumber ?? (await publicClient.getBlockNumber()) });
    const tree = synced[toHex(treeId)].tree;
    if (expectedRoot !== undefined && tree.root !== expectedRoot) {
        throw new Error(`local tree out of sync: got root ${tree.root}, expected ${expectedRoot}`);
    }
    return tree;
}

/**
 * LeanIMT proofs leave out the levels where the node is the last one and sits on the left (nothing to
 * hash with, it just moves up). The circuit wants one sibling per level, so put a 0 at those levels,
 * then pad to MAX_TREE_DEPTH. See LeafAndIndexInclusionProof in circuits/src/merkle.nr
 */
export function alignSiblings(siblings: bigint[], index: bigint, edgeIndex: bigint): bigint[] {
    const aligned: bigint[] = [];
    let next = 0;
    for (let level = 0; level < MAX_TREE_DEPTH; level++) {
        const node = index >> BigInt(level);
        const edge = edgeIndex >> BigInt(level);
        const hoisted = node === edge && node % 2n === 0n;
        aligned.push(hoisted ? 0n : siblings[next++]);
    }
    if (next !== siblings.length) {
        throw new Error(`used ${next} of ${siblings.length} siblings, index or edge index is wrong`);
    }
    return aligned;
}

/** proof of `leaf` in a synced LeanIMT, in the shape the circuit wants */
export function merkleProofInput(
    tree: { indexOf(leaf: bigint): number; generateProof(index: number): { siblings: bigint[] }; size: number },
    leaf: bigint,
): { proof: MerkleProofInput; edgeIndex: bigint } {
    const index = tree.indexOf(leaf);
    if (index < 0) throw new Error(`leaf ${leaf} is not in the tree`);
    const edgeIndex = BigInt(tree.size - 1);
    const siblings = alignSiblings(tree.generateProof(index).siblings, BigInt(index), edgeIndex);
    return { proof: { index: BigInt(index), siblings }, edgeIndex };
}

// ---------- circuit input shapes ----------

export function zeros(n: number): bigint[] {
    return new Array<bigint>(n).fill(0n);
}

export function emptyProof(): MerkleProofInput {
    return { index: 0n, siblings: zeros(MAX_TREE_DEPTH) };
}

function selectorOf(n: Note): bigint {
    return n.circuitCompSelector ?? JOIN_SPLIT_SELECTOR;
}

function storageOf(n: Note): CircuitCompStorage {
    return n.circuitCompStorage ?? ([...CIRCUIT_COMP_STORAGE_EMPTY] as CircuitCompStorage);
}

/** what `Warptoad.shield` takes: everything in the leaf except the asset and amount */
export function preCommitmentHashOf(n: Note): bigint {
    return hashPreCommitment({
        ownerHash: n.ownerHash,
        sharedNonce: n.sharedNonce,
        circuitCompSelector: selectorOf(n),
        circuitCompStorageHash: hashCircuitComponentStorage({ circuitCompStorage: storageOf(n) }),
    });
}

/** the leaf a note is inserted as */
export function hashNote(n: Note): bigint {
    return hashCommitment({ preCommitmentHash: preCommitmentHashOf(n), assetId: n.assetId, amount: n.amount });
}

/**
 * a recipient slot of the circuit. join_split only looks at `pre_commitment_hash`, `asset_id` and `amount`, other
 * circuit components (swaptoad for the maker's notes) check the fields it was hashed from too. Fakes only need a nonce
 */
export function recipientInput(n: Note): CommitmentRecipientDataInput {
    return {
        owner_hash: n.ownerHash,
        shared_nonce: n.sharedNonce,
        circuit_comp_selector: selectorOf(n),
        circuit_comp_input: [...storageOf(n)],
        asset_id: n.assetId,
        amount: n.amount,
        pre_commitment_hash: preCommitmentHashOf(n),
    };
}

/**
 * a spend slot of the circuit. `asset` is the preimage of `n.assetId`, see assets.ts: the circuit checks it hashes
 * to the note's asset_id and that the leaf's giga index is inside its range. `gigaProof` stays empty for a spend on
 * the note's own chain. Fakes only need a nonce
 */
export function spendInput(
    n: Note,
    asset: Asset,
    localProof: MerkleProofInput,
    localEdgeIndex: bigint,
    gigaProof: MerkleProofInput = emptyProof(),
): CommitmentSpendProofInput {
    return {
        commitment: {
            owner_hash: n.ownerHash,
            shared_nonce: n.sharedNonce,
            circuit_comp_selector: selectorOf(n),
            circuit_comp_storage: [...storageOf(n)],
            asset_id: n.assetId,
            amount: n.amount,
            first_giga_index: asset.firstGigaIndex,
            last_giga_index: asset.lastGigaIndex,
            wrapper_id: asset.wrapperId,
        },
        local_proof: localProof,
        giga_proof: gigaProof,
        local_edge_index: localEdgeIndex,
    };
}

/** fills an unused slot. Only the nonce matters, it makes the fake nullifier / commitment look random */
export function fakeNote(nonce: bigint): Note {
    return { ownerHash: 0n, sharedNonce: nonce, assetId: 0n, amount: 0n };
}

/** the asset of a fake slot, never checked by the circuit */
export const FAKE_ASSET: Asset = { firstGigaIndex: 0n, lastGigaIndex: 0n, wrapperId: 0n };

/** a spend slot that is not a spend. Pairs with `hashFakeNullifier(nonce)` */
export function fakeSpendInput(nonce: bigint): CommitmentSpendProofInput {
    return spendInput(fakeNote(nonce), FAKE_ASSET, emptyProof(), 0n);
}

/** pads what a circuit component signs over to CIRCUIT_COMP_AUTH_SIZE, which is what `hash_circuit_component_auth_sig` hashes */
export function authSigInputs(inputs: bigint[]): CircuitCompAuthSigInputs {
    if (inputs.length > CIRCUIT_COMP_AUTH_SIZE) throw new Error(`${inputs.length} auth inputs, the circuit takes ${CIRCUIT_COMP_AUTH_SIZE}`);
    return [...inputs, ...zeros(CIRCUIT_COMP_AUTH_SIZE - inputs.length)];
}

/**
 * no auth signature: `pub_key.x == 0` is the sentinel the circuit skips the signature check on. join_split never
 * needs one, and for swaptoad it means the owner is cancelling their own lock
 */
export function noAuth(): AuthInputs {
    return {
        pub_key: { x: 0n, y: 0n },
        signature: { x: 0n, y: 0n, scalar: 0n },
        inputs: authSigInputs([]),
    };
}

/** a recipient slot that is a normal shielded commitment, not an unshield */
export function noUnshield(): UnshieldingCommitmentInput {
    return { recipient: 0n, amount: 0n, asset_id: 0n };
}

/**
 * an unshield of `amount` of `assetId` to `recipient`
 */
export function unshieldInput(recipient: Address, assetId: bigint, amount: bigint): UnshieldingCommitmentInput {
    return { recipient: BigInt(recipient), amount, asset_id: assetId };
}

/**
 * the root part of the public inputs. TODO giga: takes the giga root and its edge index once the giga tree is
 * plugged in. Both 0 means "local spends only", the contract rejects anything else for now
 */
export function pubRoots(localRoot: bigint, localEdgeIndex: bigint, currentGigaIndex: bigint): PubRootsAndIndexesInput {
    return {
        local_root: localRoot,
        local_edge_index: localEdgeIndex,
        giga_root: 0n,
        giga_edge_index: 0n,
        current_giga_index: currentGigaIndex,
    };
}
