mod merkle;
mod hashing;
mod constants;

use crate::merkle::{
    leaf_and_index_to_root, LeafAndIndexInclusionProof, LeafInclusionProof,
};

use crate::hashing::{
    hash_circuit_contract_auth_sig, hash_circuit_contract_storage, hash_commitment,
    hash_fake_commitment, hash_fake_nullifier, hash_giga_leaf, hash_nullifier, hash_owner,
    hash_pre_commitment, hash_spend_signature_inputs,
};

use crate::constants::{
    CIRCUIT_CONTR_AUTH_SIZE, CIRCUIT_CONTR_STORAGE_EMPTY_HASH, CIRCUIT_CONTR_STORAGE_SIZE,
    CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH,
};
use eddsa::eddsa_verify;
use poseidon::{poseidon2::{self, Poseidon2}, poseidon::PoseidonHasher};
use std::string;

fn proof_local_root_to_giga_root<let MAX_DEPTH: u32>(
    proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    giga_first_valid_index: Field,
    giga_last_valid_index: Field,
) -> Field {
    assert(
        greater_or_equal(proof.index, giga_first_valid_index),
        "gigaProof index below valid_giga_index_range",
    );
    assert(
        lower_or_equal(proof.index, giga_last_valid_index),
        "gigaProof index above valid_giga_index_range",
    );
    let giga_leaf: Field = hash_giga_leaf(local_root, local_edge_index);
    leaf_and_index_to_root(proof, giga_leaf, giga_edge_index)
}

fn proof_root_of_commitments<let MAX_DEPTH: u32, let SIZE: u32>(
    spend_commitments: [CommitmentSpendProof<MAX_DEPTH>; SIZE],
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    giga_first_valid_index: Field,
    giga_last_valid_index: Field,
    owner_hash: Field,
    current_giga_index: Field,
    actual_amount_spend_commitments: u32,
) -> [ProvenCommitment; SIZE] {
    let mut proven_commitments: [ProvenCommitment; SIZE] = std::mem::zeroed();
    for index in 0..SIZE {
        let spend_commitment: CommitmentSpendProof<MAX_DEPTH> = spend_commitments[index];
        if (index < actual_amount_spend_commitments) {
            proven_commitments[index].circuit_contr_storage_hash =
                hash_circuit_contract_storage(spend_commitment.commitment.circuit_contr_storage);
            let pre_commitment_hash: Field = hash_pre_commitment(
                owner_hash,
                spend_commitment.commitment.shared_nonce,
                spend_commitment.commitment.circuit_contr_selector,
                proven_commitments[index].circuit_contr_storage_hash,
            );
            proven_commitments[index].commitment_hash = hash_commitment(
                pre_commitment_hash,
                spend_commitment.commitment.asset_id,
                spend_commitment.commitment.amount,
            );
            proven_commitments[index].local_root = leaf_and_index_to_root(
                spend_commitment.local_proof,
                proven_commitments[index].commitment_hash,
                // we trust local_edge_index for. Then verify it is the one from pub inputs if local_root==proven.local_root
                // or we verify it by following the giga_proof
                spend_commitment.local_edge_index,
            );

            // this checks if proof is on same chain, in which case we skip giga_root checks
            if (proven_commitments[index].local_root == local_root) {
                // circuit contracts will get a 0x00 giga_root
                // proven_commitment.giga_root = 0x00;
                // no lying about the giga_index or local_edge_index used!
                proven_commitments[index].giga_leaf_index = current_giga_index;
                assert(
                    local_edge_index == spend_commitment.local_edge_index,
                    "local proof skipped giga_proof but the local_edge_index was not matching the one from public inputs",
                );
            } else {
                proven_commitments[index].giga_root = proof_local_root_to_giga_root(
                    spend_commitment.giga_proof,
                    proven_commitments[index].local_root,
                    spend_commitment.local_edge_index,
                    giga_edge_index,
                    giga_first_valid_index,
                    giga_last_valid_index,
                );
                proven_commitments[index].giga_leaf_index = spend_commitment.giga_proof.index;
            }
            proven_commitments[index].amount = spend_commitment.commitment.amount;
            proven_commitments[index].asset_id = spend_commitment.commitment.asset_id;
            proven_commitments[index].circuit_contr_selector =
                spend_commitment.commitment.circuit_contr_selector;
            proven_commitments[index].circuit_contr_storage =
                spend_commitment.commitment.circuit_contr_storage;
            proven_commitments[index].local_leaf_index = spend_commitment.local_proof.index;
        } else {
            // it's a fake commitment so we make a fake_commitment hash
            // don't need this because this is not a commitment publicly inserted in the tree
            // proven_commitments[index].commitment_hash =
            //     hash_fake_commitment(spend_commitment.commitment.shared_nonce)
        }
        // fake commitments do need a share_nonce to make their fake nullifier look random
        proven_commitments[index].shared_nonce = spend_commitment.commitment.shared_nonce;
    }
    proven_commitments
}

fn verify_signature(pub_key: PubKey, signature: Signature, sig_hash: Field) -> bool {
    eddsa_verify::<PoseidonHasher>(
        pub_key.x,
        pub_key.y,
        signature.scalar,
        signature.x,
        signature.y,
        sig_hash,
    )
}

fn lower_or_equal(a: Field, b: Field) -> bool {
    !b.lt(a)
}

fn greater_or_equal(a: Field, b: Field) -> bool {
    !a.lt(b)
}

struct CommitmentProofData {
    shared_nonce: Field,
    circuit_contr_selector: Field,
    circuit_contr_storage: [Field; CIRCUIT_CONTR_STORAGE_SIZE],
    asset_id: Field,
    amount: Field,
}

struct CommitmentRecipientData {
    owner_hash: Field,
    shared_nonce: Field,
    circuit_contr_selector: Field,
    circuit_contr_input: [Field; CIRCUIT_CONTR_STORAGE_SIZE],
    asset_id: Field,
    amount: Field,
}

pub struct ProvenCommitment {
    local_root: Field,
    giga_root: Field,
    circuit_contr_selector: Field,
    circuit_contr_storage: [Field; CIRCUIT_CONTR_STORAGE_SIZE],
    circuit_contr_storage_hash: Field,
    asset_id: Field,
    amount: Field,
    commitment_hash: Field,
    giga_leaf_index: Field,
    local_leaf_index: Field,
    shared_nonce: Field,
}

struct CommitmentSpendProof<let MAX_DEPTH: u32> {
    commitment: CommitmentProofData,
    local_proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    giga_proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_edge_index: Field,
}

#[derive(Eq)]
pub struct PubKey {
    x: Field,
    y: Field,
}

pub struct Signature {
    x: Field,
    y: Field,
    scalar: Field,
}

// every time asset_id == 0, this one not un_shielding
// any index of unshielded_commitment corresponds to pub recipient_commitments_hashes
// and those should get skipped in merkle tree insertion
pub struct UnshieldingCommitment {
    recipient: Field,
    amount: Field,
    asset_id: Field,
}

pub struct PubRootsAndIndexes {
    local_root: Field, // to short circuit and skip giga_root check
    local_edge_index: Field, // ^
    giga_root: Field, // verify spend commitment
    giga_edge_index: Field, // ^
    giga_first_valid_index: Field, // ^
    giga_last_valid_index: Field, // ^
    current_giga_index: Field, // to verify owner is on this chains giga_index
}
pub struct TimeStamps {
    //timestamps: never possible the read the exact time rn, but with these 2 you can get a range
    proof_expire_time_stamp: Field,
    historic_time_stamp: Field,
}

pub struct PubInputs<let SIZE: u32> {
    roots: PubRootsAndIndexes,
    time_stamps: TimeStamps,
    public_hash: Field, // anything done in public is in here, encrypted blobs, contract calls, etc, attached to spenders signature and constrained to proof shared to relayer
    unshielding_commitments: [UnshieldingCommitment; SIZE],
    nullifiers: [Field; SIZE], // to make `spend_commitments` un spendable
    recipient_commitments_hashes: [Field; SIZE],
}

pub struct OwnerInputs {
    pub_key: PubKey,
    nullifier_secret: Field,
    signature: Signature
}

pub struct AuthInputs<let AUTH_HASH_SIZE:u32> {
    pub_key: PubKey,
    signature: Signature,
    inputs: [Field; AUTH_HASH_SIZE]
}

pub struct PrivInputs<let DEPTH: u32, let SIZE: u32, let AUTH_HASH_SIZE: u32> {
    recipient_commitments: [CommitmentRecipientData; SIZE],
    actual_amount_recipient_commitments: u32,
    // proof
    spend_commitments: [CommitmentSpendProof<DEPTH>; SIZE], // to proof owner owns things
    actual_amount_spend_commitments: u32, // might want to only consume 1 for example
    //signed_data: PrivateSignedData, // get rid of this. Just sign hash of all recipient_commitments + spend_commitments
    // bad actors can't use the signature to steal funds or nullify shit you didn't intend to nullify
    // add public_hash and withdraw address, contract calls, or abstracted accounts calls are now also solid
    // dont need timestamps, these are only used as source of truth not intent, same with root data
    // secret owner data
    owner: OwnerInputs,
    auth: AuthInputs<AUTH_HASH_SIZE>,
    // for now just one selector instead of contract_selector + function_selector
    // this selector is to validate the spend logic, join_split will call any circuit_contract with given inputs
    // based on selectors and inputs in recipient_commitments
    // you can only spend from one circuit_contract at the time, this is to make joins easier to implement
    // since it's very chill to work with all the same spend_commitments, so you can just add up amounts
    circuit_contr_selector: Field,
}

// TODO remember to pad timestamps a bit, by just waiting a extra random amount of time. So not to finger print txs proof time
// TODO remember to domain separate fake nullifiers and commitments,
fn main(
    pub_in: pub PubInputs<CIRCUIT_SIZE>,
    priv_in: PrivInputs<MAX_TREE_DEPTH, CIRCUIT_SIZE, CIRCUIT_CONTR_AUTH_SIZE>,
) {
    let owner_hash: Field = hash_owner(priv_in.owner.pub_key, pub_in.roots.current_giga_index, priv_in.owner.nullifier_secret);
    // @warning: THESE COMMITMENTS ARE NOT VERIFIED, only that commitment+proof = root, but THAT ROOT CAN BE INVALID
    // the `circuit_contract` functions below should check if those roots are valid!
    let spend_commitments_and_roots: [ProvenCommitment; CIRCUIT_SIZE] =
        // local_root is passed here, ONLY TO SKIP giga_root proof checks. IT IS NOT VERIFIED
        proof_root_of_commitments(
            priv_in.spend_commitments,
            pub_in.roots.local_root,
            pub_in.roots.local_edge_index,
            pub_in.roots.giga_edge_index,
            pub_in.roots.giga_first_valid_index,
            pub_in.roots.giga_last_valid_index,
            owner_hash,
            pub_in.roots.current_giga_index,
            priv_in.actual_amount_spend_commitments,
        );

    let spend_sig_hash: Field = hash_spend_signature_inputs(
        pub_in.public_hash,
        spend_commitments_and_roots,
        pub_in.recipient_commitments_hashes,
    );
    assert(
        verify_signature(priv_in.owner.pub_key, priv_in.owner.signature, spend_sig_hash),
        "invalid spend signature",
    );

    if (priv_in.auth.inputs != std::mem::zeroed()) {
        let auth_sig_hash: Field = hash_circuit_contract_auth_sig(priv_in.auth.inputs);
        assert(
            verify_signature(priv_in.auth.pub_key, priv_in.auth.signature, auth_sig_hash),
            "invalid auth signature",
        );
    }
    //
    //  @WARNING: the contract_circuits below need to at least verify 3 things:
    //      -every root in `spend_commitments_and_roots`, all contain valid roots
    //      -signer, in `signer_owner_secrets` is allowed to nullify and spend these commitment
    //          ex in join_split, because they are in that commitments
    //          or in closing a swap, it is proven that counter party has access to the other locked funds
    //      -commitment being spend contains the expected: `circuit_contract` domain separator
    //
    // Fuck any of that up and you quickly have INFINITE MINT BUGS or stolen funds
    //

    // first one pick what to spend from
    if (priv_in.circuit_contr_selector == JOIN_SPLIT_SELECTOR) {
        // TODO nullifier = h(nullifier_secret, giga_index, local_index)
        // for commitment emitting multiple nullifiers like swap_maker_lock_contract needing closed_nullifier, timer_started_nullifier
        // just add a nullifier slot number
        join_split(
            CircuitContrInputs {
                local_root: pub_in.roots.local_root,
                giga_root: pub_in.roots.giga_root,
                proof_expire_time_stamp: pub_in.time_stamps.proof_expire_time_stamp,
                historic_time_stamp: pub_in.time_stamps.historic_time_stamp,
                public_hash: pub_in.public_hash,
                unshielding_commitments: pub_in.unshielding_commitments,
                nullifiers: pub_in.nullifiers,
                recipient_commitments_hashes: pub_in.recipient_commitments_hashes,
                recipient_commitments: priv_in.recipient_commitments,
                actual_amount_recipient_commitments: priv_in.actual_amount_recipient_commitments,
                spend_commitments_and_roots: spend_commitments_and_roots,
                actual_amount_spend_commitments: priv_in.actual_amount_spend_commitments,
                nullifier_secret: priv_in.owner.nullifier_secret,
                auth_sig_inputs: priv_in.auth.inputs,
                owner_hash,
            },
        )
    } else {
        assert(false, "unknown signed_data.circuit_contract_selector");
    }

    // @WARNING every circuit contract should either block unshield by doing assert(unshielding_commitment.asset_id == 0x00)
    // or correctly check accounting on these unshielding_commitments
    for index in 0..CIRCUIT_SIZE {
        let unshielding_commitment: UnshieldingCommitment = pub_in.unshielding_commitments[index];
        let recipient_commitment: CommitmentRecipientData = priv_in.recipient_commitments[index];

        // only non fakes can unshield so only those get the asserts of:
        // unshielding_commitment.thing == recipient_commitment.thing
        if (index < priv_in.actual_amount_recipient_commitments) {
            // now just check if pub inputs actually intent to unshield
            if (unshielding_commitment.asset_id != 0x00) {
                assert(
                    unshielding_commitment.asset_id == recipient_commitment.asset_id,
                    "unshielding_commitment asset_id mismatch",
                );
                assert(
                    unshielding_commitment.amount == recipient_commitment.amount,
                    "unshielding_commitment asset_id mismatch",
                );
                // note: sender does not usually know what pub_key the owner_hash has, we could add it so we can have more natural reading code
                // where the unshielding public ethereum address is stored where normally we store the pub spending key
                // but instead we just use the owner_hash instead so we skip adding inputs to recipient_commitments struct and addition poseidon2 hashes!
                // afaik railgun solves this by just revealing the entire commitment leaf onchain, but that adds 3 poseidon2 hashes in solidity for us
                // and 4 permutations in total. That is expensive!
                assert(
                    unshielding_commitment.recipient == recipient_commitment.owner_hash,
                    "unshielding_commitment.recipient does not match recipient_commitment.owner_hash",
                );
            }
        } else {
            // fake is fake, no fake commitments unshielding into real money!!
            assert(unshielding_commitment.asset_id == 0x00, "fake slot cannot unshield");
        }
    }
}

pub struct CircuitContrInputs<let SIZE: u32> {
    local_root: Field,
    giga_root: Field,
    proof_expire_time_stamp: Field,
    historic_time_stamp: Field,
    unshielding_commitments: [UnshieldingCommitment; SIZE],
    public_hash: Field, // here you can constrain what is done in public
    nullifiers: [Field; SIZE],
    recipient_commitments_hashes: [Field; SIZE],
    recipient_commitments: [CommitmentRecipientData; SIZE],
    actual_amount_recipient_commitments: u32,
    spend_commitments_and_roots: [ProvenCommitment; SIZE],
    actual_amount_spend_commitments: u32,
    nullifier_secret: Field,
    auth_sig_inputs: [Field; CIRCUIT_CONTR_AUTH_SIZE],
    owner_hash: Field,
}

// this guy has no inputs!
fn hash_join_split_inputs<let SIZE: u32>(inputs: CircuitContrInputs<SIZE>) -> Field {
    CIRCUIT_CONTR_STORAGE_EMPTY_HASH
}

// TODO dummy nullifiers and commitment_hashes
fn join_split<let SIZE: u32>(inputs: CircuitContrInputs<SIZE>) {
    // only one asset at the time pls
    let expected_asset_id: Field = inputs.spend_commitments_and_roots[0].asset_id;
    let mut spendable: Field = 0;
    let mut spend: Field = 0;
    for index in 0..SIZE {
        // ----------- spend commitment --------------------------
        let spend_commitment: ProvenCommitment = inputs.spend_commitments_and_roots[index];
        let mut nullifier: Field = 0x00;
        if (index < inputs.actual_amount_spend_commitments) {
            // check root
            if (spend_commitment.giga_root == 0x00) {
                assert(
                    spend_commitment.local_root == inputs.local_root,
                    "spend was local only but does not match local_root from public inputs",
                );
            } else {
                assert(
                    spend_commitment.giga_root == inputs.giga_root,
                    "spend was *not* local and does not match giga_root from public inputs",
                );
            }
            // other checks
            assert(
                spend_commitment.circuit_contr_selector == JOIN_SPLIT_SELECTOR,
                "The first commitment in spend_commitments was set to JOIN_SPLIT, but another was found set to a different circuit contract. Please only spend from one circuit contract at a time.",
            );
            assert(
                expected_asset_id == spend_commitment.asset_id,
                "spend_commitments does not contain all same assetIds",
            );

            nullifier = hash_nullifier(
                inputs.nullifier_secret,
                spend_commitment.giga_leaf_index,
                spend_commitment.local_leaf_index,
            );
            spendable += spend_commitment.amount;
        } else {
            // we ignore it, and don't add it to spendable amount
            // TODO make sure nullifier is fake and not trying to nullify someone else!
            nullifier = hash_fake_nullifier(spend_commitment.shared_nonce);
        }
        assert(nullifier == inputs.nullifiers[index], "nullifier mismatch");

        // ------------- recipients commitment ----------------------------------------
        let recipient_commitment: CommitmentRecipientData = inputs.recipient_commitments[index];
        let mut recipient_commitment_hash: Field = 0x00;
        if (index < inputs.actual_amount_recipient_commitments) {
            let mut recipient_storage_hash: Field = CIRCUIT_CONTR_STORAGE_EMPTY_HASH;
            if (recipient_commitment.circuit_contr_selector == JOIN_SPLIT_SELECTOR) {
                recipient_storage_hash = hash_join_split_inputs(inputs)
            } else {
                assert(
                    false,
                    "unknown circuit_contr_selector in recipient_commitments when trying to call a circuit contract",
                );
            };
            assert(
                expected_asset_id == recipient_commitment.asset_id,
                "recipient_commitments does not contain all same assetIds",
            );

            // track amounts
            spend += recipient_commitment.amount;
            // TODO this works right? Also spendable does need this right? If total supply is < FIELD_LIMIT?
            assert(lower_or_equal(recipient_commitment.amount, spend), "spend overflowed");

            // TODO hoist this out of here so other circuit contracts don't do double works hashing like this
            // and check here:
            // recipient_commitment_hash == inputs.recipient_commitments_hashes[index]
            // expected_asset_id == recipient_commitment.asset_id
            // recipient_storage_hash == recipient_commitment.circuit_contr_storage_hash
            let pre_commitment_hash: Field = hash_pre_commitment(
                recipient_commitment.owner_hash,
                recipient_commitment.shared_nonce,
                recipient_commitment.circuit_contr_selector,
                recipient_storage_hash,
            );
            recipient_commitment_hash = hash_commitment(
                pre_commitment_hash,
                expected_asset_id,
                recipient_commitment.amount,
            );
        } else {
            // nothing spend
            recipient_commitment_hash = hash_fake_commitment(recipient_commitment.shared_nonce);
        }
        assert(
            recipient_commitment_hash == inputs.recipient_commitments_hashes[index],
            "a commitment_hash from public inputs does not match the recipient_commitment inputs hashed in circuit",
        );
    }
    assert(lower_or_equal(spend, spendable), "not enough funds");
}
