import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WARPTOAD_CONTRACT_NAME } from "./config.js";
import type { CircuitCompAuthSigInputs, CircuitCompStorage, CircuitSizeFields, PubKey } from "./hashing.js";

export type WarptoadContract = ContractReturnType<typeof WARPTOAD_CONTRACT_NAME>;
export type WrapperFactoryContract = ContractReturnType<"WrapperFactory">;
export type WrapperERC20Contract = ContractReturnType<"WrapperERC20">;
export type ChainConfigContract = ContractReturnType<"ChainConfig">;

/**
 * the preimage of a note's `assetId`, see `hashAssetId` in hashing.ts and assets.ts. A wallet needs it to spend,
 * the blob only carries the hash. `resolveAsset` in assets.ts gets it back from the contracts
 */
export type Asset = { firstGigaIndex: bigint; lastGigaIndex: bigint; wrapperId: bigint };

// ------ what a wallet keeps ------

/** everything that goes into a commitment, minus the owner's secrets. Sender and recipient both know this */
export type Note = {
    ownerHash: bigint;
    sharedNonce: bigint;
    assetId: bigint;
    amount: bigint;
    /** defaults to JOIN_SPLIT_SELECTOR */
    circuitCompSelector?: bigint;
    /** defaults to CIRCUIT_COMP_STORAGE_EMPTY */
    circuitCompStorage?: CircuitCompStorage;
};

// ------ mirrors of the structs in circuits/src/main.nr ------
// snake_case on purpose: these are handed to noir_js as is

/** `LeafAndIndexInclusionProof`: one sibling per level, 0 at hoisted levels, padded to MAX_TREE_DEPTH */
export type MerkleProofInput = { index: bigint; siblings: bigint[] };

export type SignatureInput = { x: bigint; y: bigint; scalar: bigint };

export type CommitmentProofDataInput = {
    shared_nonce: bigint;
    circuit_comp_selector: bigint;
    circuit_comp_storage: bigint[];
    asset_id: bigint;
    amount: bigint;
    /** preimage of `asset_id`, the circuit checks the hash and that the spent leaf's giga index is in the range */
    first_giga_index: bigint;
    last_giga_index: bigint;
    wrapper_id: bigint;
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
    circuit_comp_selector: bigint;
    circuit_comp_input: bigint[];
    asset_id: bigint;
    amount: bigint;
};

export type UnshieldingCommitmentInput = { recipient: bigint; amount: bigint; asset_id: bigint };

export type PubRootsAndIndexesInput = {
    local_root: bigint;
    local_edge_index: bigint;
    giga_root: bigint;
    giga_edge_index: bigint;
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

export type AuthInputs = { pub_key: PubKey; signature: SignatureInput; inputs: CircuitCompAuthSigInputs };

/** `PublicHashPreimage`: Poseidon2 of these two is `public_hash`, see `publicHashOf` in messages.ts */
export type PublicHashPreimageInput = { messages_hash: bigint; other_hash: bigint };

export type PrivInputs = {
    public_hash_preimage: PublicHashPreimageInput;
    recipient_commitments: CommitmentRecipientDataInput[];
    /** u32 in the circuit, so a number */
    actual_amount_recipient_commitments: number;
    spend_commitments: CommitmentSpendProofInput[];
    /** u32 in the circuit, so a number */
    actual_amount_spend_commitments: number;
    owner: OwnerInputs;
    auth: AuthInputs;
    circuit_comp_selector: bigint;
};

/** the two arguments of `main` */
export type CircuitInputs = { pub_in: PubInputs; priv_in: PrivInputs };
