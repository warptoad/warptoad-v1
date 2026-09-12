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
import {
    CIRCUIT_CONTR_AUTH_SIZE,
    CIRCUIT_CONTR_STORAGE_EMPTY,
    CIRCUIT_CONTR_STORAGE_SIZE,
    JOIN_SPLIT_SELECTOR,
    MAX_TREE_DEPTH,
} from "./constants.js";
import {
    hashCircuitContractStorage,
    hashCommitment,
    hashPreCommitment,
    type CircuitContrAuthSigInputs,
    type CircuitContrStorage,
} from "./hashing.js";
import type {
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
    return n.circuitContrSelector ?? JOIN_SPLIT_SELECTOR;
}

function storageOf(n: Note): CircuitContrStorage {
    return n.circuitContrStorage ?? ([...CIRCUIT_CONTR_STORAGE_EMPTY] as CircuitContrStorage);
}

/** the leaf a note is inserted as */
export function hashNote(n: Note): bigint {
    return hashCommitment({
        preCommitmentHash: hashPreCommitment({
            ownerHash: n.ownerHash,
            sharedNonce: n.sharedNonce,
            circuitContrSelector: selectorOf(n),
            circuitContrStorageHash: hashCircuitContractStorage({ circuitContrStorage: storageOf(n) }),
        }),
        assetId: n.assetId,
        amount: n.amount,
    });
}

/**
 * a recipient slot of the circuit. `circuitContrInput` is what the recipient's circuit contract
 * constructor gets, join_split ignores it. Fakes only need a nonce
 */
export function recipientInput(n: Note, circuitContrInput: bigint[] = zeros(CIRCUIT_CONTR_STORAGE_SIZE)): CommitmentRecipientDataInput {
    return {
        owner_hash: n.ownerHash,
        shared_nonce: n.sharedNonce,
        circuit_contr_selector: selectorOf(n),
        circuit_contr_input: circuitContrInput,
        asset_id: n.assetId,
        amount: n.amount,
    };
}

/** a spend slot of the circuit. `gigaProof` stays empty for a spend on the note's own chain. Fakes only need a nonce */
export function spendInput(
    n: Note,
    localProof: MerkleProofInput,
    localEdgeIndex: bigint,
    gigaProof: MerkleProofInput = emptyProof(),
): CommitmentSpendProofInput {
    return {
        commitment: {
            shared_nonce: n.sharedNonce,
            circuit_contr_selector: selectorOf(n),
            circuit_contr_storage: [...storageOf(n)],
            asset_id: n.assetId,
            amount: n.amount,
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

/** a spend slot that is not a spend. Pairs with `hashFakeNullifier(nonce)` */
export function fakeSpendInput(nonce: bigint): CommitmentSpendProofInput {
    return spendInput(fakeNote(nonce), emptyProof(), 0n);
}

/** join_split doesn't use the auth signature, so it stays all zeros and the circuit skips it */
export function noAuth(): AuthInputs {
    return {
        pub_key: { x: 0n, y: 0n },
        signature: { x: 0n, y: 0n, scalar: 0n },
        inputs: zeros(CIRCUIT_CONTR_AUTH_SIZE) as CircuitContrAuthSigInputs,
    };
}

/** a recipient slot that is a normal shielded commitment, not an unshield */
export function noUnshield(): UnshieldingCommitmentInput {
    return { recipient: 0n, amount: 0n, asset_id: 0n };
}

/** an unshield of `amount` of `assetId` to `recipient`, matching a recipient note with the address as owner hash */
export function unshieldInput(recipient: Address, assetId: bigint, amount: bigint): UnshieldingCommitmentInput {
    return { recipient: BigInt(recipient), amount, asset_id: assetId };
}

/**
 * the root part of the public inputs. TODO giga: takes the giga root, its edge index and the contract's
 * valid index range once the giga tree is plugged in. All 0 means "local spends only"
 */
export function pubRoots(localRoot: bigint, localEdgeIndex: bigint, currentGigaIndex: bigint): PubRootsAndIndexesInput {
    return {
        local_root: localRoot,
        local_edge_index: localEdgeIndex,
        giga_root: 0n,
        giga_edge_index: 0n,
        giga_first_valid_index: 0n,
        giga_last_valid_index: 0n,
        current_giga_index: currentGigaIndex,
    };
}
