import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WARPTOAD_CONTRACT_NAME } from "./config.js";
import type { CircuitContrAuthSigInputs, CircuitContrStorage, CircuitSizeFields, PubKey } from "./hashing.js";

export type WarptoadContract = ContractReturnType<typeof WARPTOAD_CONTRACT_NAME>;

// ------ what a wallet keeps ------

/** everything that goes into a commitment, minus the owner's secrets. Sender and recipient both know this */
export type Note = {
    ownerHash: bigint;
    sharedNonce: bigint;
    assetId: bigint;
    amount: bigint;
    /** defaults to JOIN_SPLIT_SELECTOR */
    circuitContrSelector?: bigint;
    /** defaults to CIRCUIT_CONTR_STORAGE_EMPTY */
    circuitContrStorage?: CircuitContrStorage;
};

// ------ mirrors of the structs in circuits/src/main.nr ------
// snake_case on purpose: these are handed to noir_js as is

/** `LeafAndIndexInclusionProof`: one sibling per level, 0 at hoisted levels, padded to MAX_TREE_DEPTH */
export type MerkleProofInput = { index: bigint; siblings: bigint[] };

export type SignatureInput = { x: bigint; y: bigint; scalar: bigint };

export type CommitmentProofDataInput = {
    shared_nonce: bigint;
    circuit_contr_selector: bigint;
    circuit_contr_storage: bigint[];
    asset_id: bigint;
    amount: bigint;
};

export type CommitmentSpendProofInput = {
    commitment: CommitmentProofDataInput;
    local_proof: MerkleProofInput;
    giga_proof: MerkleProofInput;
    local_edge_index: bigint;
};

export type CommitmentRecipientDataInput = {
    owner_hash: bigint;
    shared_nonce: bigint;
    circuit_contr_selector: bigint;
    circuit_contr_input: bigint[];
    asset_id: bigint;
    amount: bigint;
};

export type UnshieldingCommitmentInput = { recipient: bigint; amount: bigint; asset_id: bigint };

export type PubRootsAndIndexesInput = {
    local_root: bigint;
    local_edge_index: bigint;
    giga_root: bigint;
    giga_edge_index: bigint;
    giga_first_valid_index: bigint;
    giga_last_valid_index: bigint;
    current_giga_index: bigint;
};

export type TimeStampsInput = { proof_expire_time_stamp: bigint; historic_time_stamp: bigint };

export type PubInputs = {
    roots: PubRootsAndIndexesInput;
    time_stamps: TimeStampsInput;
    public_hash: bigint;
    unshielding_commitments: UnshieldingCommitmentInput[];
    nullifiers: CircuitSizeFields;
    recipient_commitments_hashes: CircuitSizeFields;
};

export type OwnerInputs = { pub_key: PubKey; nullifier_secret: bigint; signature: SignatureInput };

export type AuthInputs = { pub_key: PubKey; signature: SignatureInput; inputs: CircuitContrAuthSigInputs };

export type PrivInputs = {
    recipient_commitments: CommitmentRecipientDataInput[];
    /** u32 in the circuit, so a number */
    actual_amount_recipient_commitments: number;
    spend_commitments: CommitmentSpendProofInput[];
    /** u32 in the circuit, so a number */
    actual_amount_spend_commitments: number;
    owner: OwnerInputs;
    auth: AuthInputs;
    circuit_contr_selector: bigint;
};

/** the two arguments of `main` */
export type CircuitInputs = { pub_in: PubInputs; priv_in: PrivInputs };
