mod merkle;
mod hashing;
mod constants;

use crate::merkle::{leaf_and_index_to_root, LeafAndIndexInclusionProof, LeafInclusionProof};

use crate::hashing::{
    hash_asset_id, hash_circuit_component_auth_sig, hash_circuit_component_storage, hash_commitment,
    hash_fake_commitment, hash_fake_nullifier, hash_giga_leaf, hash_nullifier, hash_owner,
    hash_owner_keys, hash_pre_commitment, hash_public, hash_shared_nonce_swaptoad,
    hash_spend_signature_inputs,
};

use crate::constants::{
    CIRCUIT_COMP_AUTH_SIZE, CIRCUIT_COMP_STORAGE_EMPTY_HASH, CIRCUIT_COMP_STORAGE_SIZE,
    CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH, SWAP_TOAD_SELECTOR,
};
use eddsa::eddsa_verify;
use poseidon::{poseidon2::{self, Poseidon2}, poseidon::PoseidonHasher};

fn proof_local_root_to_giga_root<let MAX_DEPTH: u32>(
    proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
) -> Field {
    let giga_leaf: Field = hash_giga_leaf(local_root, local_edge_index);
    leaf_and_index_to_root(proof, giga_leaf, giga_edge_index)
}

fn check_giga_range(first_giga_index: Field, last_giga_index: Field, giga_index: Field) {
    assert(
        greater_or_equal(giga_index, first_giga_index),
        "gigaProof index below first_giga_index",
    );
    assert(lower_or_equal(giga_index, last_giga_index), "gigaProof index above last_giga_index");
}

fn proof_root_of_commitments<let MAX_DEPTH: u32, let SIZE: u32>(
    spend_commitments: [CommitmentSpendProof<MAX_DEPTH>; SIZE],
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    current_giga_index: Field,
    actual_amount_spend_commitments: u32,
) -> [ProvenCommitment; SIZE] {
    let mut proven_commitments: [ProvenCommitment; SIZE] = std::mem::zeroed();
    for index in 0..SIZE {
        let spend_commitment: CommitmentSpendProof<MAX_DEPTH> = spend_commitments[index];
        if (index < actual_amount_spend_commitments) {
            proven_commitments[index].circuit_comp_storage_hash =
                hash_circuit_component_storage(spend_commitment.commitment.circuit_comp_storage);
            let pre_commitment_hash: Field = hash_pre_commitment(
                spend_commitment.commitment.owner_hash,
                spend_commitment.commitment.shared_nonce,
                spend_commitment.commitment.circuit_comp_selector,
                proven_commitments[index].circuit_comp_storage_hash,
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

            let hashed_asset_id: Field = hash_asset_id(
                spend_commitment.commitment.first_giga_index,
                spend_commitment.commitment.last_giga_index,
                spend_commitment.commitment.wrapper_id,
            );
            assert(spend_commitment.commitment.asset_id == hashed_asset_id, "incorrect asset_id");
            // this handles the fact that giga tree is now permissionless
            // this blocks bad actors exploiting a infinite mint bug, where they could just make a new giga_leaf
            // and put anything they want in there. Like asset_id of warptoadETH and then set the amount to way too much! :0
            // They can still do that, but the circuit will never treat it as spendable since that asset_id also needs
            // the giga index range set by the wrapper factory.
            // And the wrapper factory only trust it's own range of indexes. Where only wrapperFactory can update the leaf

            // this checks if proof is on same chain, in which case we skip giga_root checks
            if (proven_commitments[index].local_root == local_root) {
                // circuit components will get a 0x00 giga_root
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
                );
                proven_commitments[index].giga_leaf_index = spend_commitment.giga_proof.index;
            }
            check_giga_range(
                spend_commitment.commitment.first_giga_index,
                spend_commitment.commitment.last_giga_index,
                proven_commitments[index].giga_leaf_index,
            );
            proven_commitments[index].amount = spend_commitment.commitment.amount;
            proven_commitments[index].asset_id = spend_commitment.commitment.asset_id;
            proven_commitments[index].circuit_comp_selector =
                spend_commitment.commitment.circuit_comp_selector;
            proven_commitments[index].circuit_comp_storage =
                spend_commitment.commitment.circuit_comp_storage;
            proven_commitments[index].local_leaf_index = spend_commitment.local_proof.index;
            // @notice owner_keys_hash is not constraint to owner_hash, this is confusing since we say this is a "proven commitment"
            proven_commitments[index].owner_keys_hash = spend_commitment.commitment.owner_keys_hash;
            proven_commitments[index].owner_hash = spend_commitment.commitment.owner_hash
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
    owner_hash: Field,
    owner_keys_hash: Field,
    shared_nonce: Field,
    circuit_comp_selector: Field,
    circuit_comp_storage: [Field; CIRCUIT_COMP_STORAGE_SIZE],
    asset_id: Field,
    amount: Field,
    first_giga_index: Field,
    last_giga_index: Field,
    wrapper_id: Field,
}

struct CommitmentRecipientData {
    owner_hash: Field,
    shared_nonce: Field,
    circuit_comp_selector: Field,
    circuit_comp_input: [Field; CIRCUIT_COMP_STORAGE_SIZE],
    asset_id: Field,
    amount: Field,
    pre_commitment_hash: Field,
}

pub struct ProvenCommitment {
    owner_hash: Field,
    local_root: Field,
    giga_root: Field,
    circuit_comp_selector: Field,
    circuit_comp_storage: [Field; CIRCUIT_COMP_STORAGE_SIZE],
    circuit_comp_storage_hash: Field,
    asset_id: Field,
    amount: Field,
    commitment_hash: Field,
    giga_leaf_index: Field,
    local_leaf_index: Field,
    shared_nonce: Field,
    owner_keys_hash: Field,
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
    public_hash: Field,
    first_message_hash: Field,
    unshielding_commitments: [UnshieldingCommitment; SIZE],
    nullifiers: [Field; SIZE], // to make `spend_commitments` un spendable
    recipient_commitments_hashes: [Field; SIZE],
}

pub struct OwnerInputs {
    pub_key: PubKey,
    nullifier_secret: Field,
    signature: Signature,
}

pub struct AuthInputs<let AUTH_HASH_SIZE: u32> {
    pub_key: PubKey,
    signature: Signature,
    inputs: [Field; AUTH_HASH_SIZE],
}

/// see hash_public. `first_message_hash` is here so a circuit component can constrain what the sender put in the messages
pub struct PublicHashPreimage {
    first_message_hash: Field,
    other_hash: Field,
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
    // this selector is to validate the spend logic, join_split will call any circuit_component with given inputs
    // based on selectors and inputs in recipient_commitments
    // you can only spend from one circuit_component at the time, this is to make joins easier to implement
    // since it's very chill to work with all the same spend_commitments, so you can just add up amounts
    circuit_comp_selector: Field,
}

// TODO remember to pad timestamps a bit, by just waiting a extra random amount of time. So not to finger print txs proof time
// TODO remember to domain separate fake nullifiers and commitments,
fn main(
    pub_in: pub PubInputs<CIRCUIT_SIZE>,
    priv_in: PrivInputs<MAX_TREE_DEPTH, CIRCUIT_SIZE, CIRCUIT_COMP_AUTH_SIZE>,
) {
    let owner_keys_hash: Field =
        hash_owner_keys(priv_in.owner.pub_key, priv_in.owner.nullifier_secret);
    let owner_hash: Field = hash_owner(owner_keys_hash, pub_in.roots.current_giga_index);
    // @warning: THESE COMMITMENTS ARE NOT VERIFIED, only that commitment+proof = root, but THAT ROOT CAN BE INVALID
    // the `circuit_component` functions below should check if those roots are valid!
    let spend_commitments_and_roots: [ProvenCommitment; CIRCUIT_SIZE] =
        // local_root is passed here, ONLY TO SKIP giga_root proof checks. IT IS NOT VERIFIED
        proof_root_of_commitments(
            priv_in.spend_commitments,
            pub_in.roots.local_root,
            pub_in.roots.local_edge_index,
            pub_in.roots.giga_edge_index,
            pub_in.roots.current_giga_index,
            priv_in.actual_amount_spend_commitments,
        );

    let spend_sig_hash: Field = hash_spend_signature_inputs(
        pub_in.public_hash,
        spend_commitments_and_roots,
        pub_in.recipient_commitments_hashes,
    );
    assert(
        verify_signature(
            priv_in.owner.pub_key,
            priv_in.owner.signature,
            spend_sig_hash,
        ),
        "invalid spend signature",
    );

    if (priv_in.auth.pub_key.x != 0x00) {
        let auth_sig_hash: Field = hash_circuit_component_auth_sig(priv_in.auth.inputs);
        assert(
            verify_signature(priv_in.auth.pub_key, priv_in.auth.signature, auth_sig_hash),
            "invalid auth signature",
        );
    }
    //
    //  @WARNING: the contract_circuits below needs to at least verify 3 things:
    //      -every root in `spend_commitments_and_roots`, all contain valid roots
    //      -signer, in `signer_owner_secrets` is allowed to nullify and spend these commitment
    //          ex in join_split, because they are in that commitments
    //          or in closing a swap, it is proven that counter party has access to the other locked funds
    //      -commitment being spend contains the expected: `circuit_component` domain separator
    //
    // Fuck any of that up and you quickly have INFINITE MINT BUGS or stolen funds
    //

    // first one pick what to spend from
    let circuit_comp_inputs: CircuitCompInputs<CIRCUIT_SIZE> = CircuitCompInputs {
        local_root: pub_in.roots.local_root,
        giga_root: pub_in.roots.giga_root,
        current_giga_index: pub_in.roots.current_giga_index,
        proof_expire_time_stamp: pub_in.time_stamps.proof_expire_time_stamp,
        historic_time_stamp: pub_in.time_stamps.historic_time_stamp,
        first_message_hash: pub_in.first_message_hash,
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
        auth_sig_pubkey: priv_in.auth.pub_key,
        owner_hash,
    };

    if (priv_in.circuit_comp_selector == JOIN_SPLIT_SELECTOR) {
        // TODO nullifier = h(nullifier_secret, giga_index, local_index)
        // for commitment emitting multiple nullifiers like swap_maker_lock_contract needing closed_nullifier, timer_started_nullifier
        // just add a nullifier slot number
        join_split(circuit_comp_inputs);
    } else if priv_in.circuit_comp_selector == SWAP_TOAD_SELECTOR {
        swaptoad(circuit_comp_inputs);
    } else {
        assert(false, "unknown signed_data.circuit_component_selector");
    }

    // @WARNING every circuit component should either block unshield by doing assert(unshielding_commitment.asset_id == 0x00)
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
                    "unshielding_commitment amount mismatch",
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

pub struct CircuitCompInputs<let SIZE: u32> {
    local_root: Field,
    giga_root: Field,
    current_giga_index: Field,
    proof_expire_time_stamp: Field,
    historic_time_stamp: Field,
    unshielding_commitments: [UnshieldingCommitment; SIZE],
    first_message_hash: Field,
    public_hash: Field, // here you can constrain what is done in public
    nullifiers: [Field; SIZE],
    recipient_commitments_hashes: [Field; SIZE],
    recipient_commitments: [CommitmentRecipientData; SIZE],
    actual_amount_recipient_commitments: u32,
    spend_commitments_and_roots: [ProvenCommitment; SIZE],
    actual_amount_spend_commitments: u32,
    nullifier_secret: Field,
    auth_sig_inputs: [Field; CIRCUIT_COMP_AUTH_SIZE],
    auth_sig_pubkey: PubKey,
    owner_hash: Field,
}

// TODO nothing in this that is signed binds to a specific commitment
// a nice flexibility but maybe dangerous? Signing off on i want to trade a for b
// and then suddenly they use a commitment you didn't intend on being spend is
// not horrible. But might be awkward if you are already talking with another counter party
// but that is not scary enough for me
// simple fix is to only use one auth pubkey per live locked commitment!
pub struct SwapToadOrder {
    listing_asset_id: Field,
    listing_amount: Field,
    payment_asset_id: Field,
    payment_amount: Field,
    expiry: Field,
    first_message_hash: Field,
    maker_pre_commitment_hash: Field,
}

pub struct SwapToadStorage {
    auth: PubKey,
    shared_nullifier_secret: Field,
}

fn check_root<let STRING_SIZE: u32, let SIZE: u32>(
    commitment: ProvenCommitment,
    inputs: CircuitCompInputs<SIZE>,
    // just for debug
    commitment_name: str<STRING_SIZE>,
) {
    if commitment.giga_root == 0 {
        assert(
            commitment.local_root == inputs.local_root,
            f"commitment: {commitment_name} spend was local only but does not match local_root from public inputs",
        );
    } else {
        assert(
            commitment.giga_root == inputs.giga_root,
            f"commitment: {commitment_name} spend was *not* local and does not match giga_root from public inputs",
        );
    }
}

// @notice: maker locks tokens into a toad_swap lock by creating commitments with circuit_comp_selector set to TOAD_SWAP_SELECTOR
// and **any** value they want into circuit_comp_storage_hash!
// this function is ran to proof a toad_swap is filled
fn swaptoad<let SIZE: u32>(inputs: CircuitCompInputs<SIZE>) {
    let locked_commitment: ProvenCommitment = inputs.spend_commitments_and_roots[0];
    // check root
    check_root(locked_commitment, inputs, "locked_commitment");
    // check selector
    assert(
        locked_commitment.circuit_comp_selector == SWAP_TOAD_SELECTOR,
        "locked_commitment being spend needs it's circuit_comp_selector to be set to TOAD_SWAP_SELECTOR",
    );

    // TODO document first slot is pubkey of signer of the order
    let lock_storage: SwapToadStorage = SwapToadStorage {
        auth: PubKey {
            x: locked_commitment.circuit_comp_storage[0],
            y: locked_commitment.circuit_comp_storage[1],
        },
        shared_nullifier_secret: locked_commitment.circuit_comp_storage[2],
    };
    let maker_change_commit: CommitmentRecipientData = inputs.recipient_commitments[0];
    let mut taker_spend_nullfier: Field = 0x00;
    let mut maker_new_commit_hash: Field = 0x00;
    let mut taker_change_commit_hash: Field = 0x00;
    let mut taker_new_commit_hash: Field = 0x00;
    assert(
        maker_change_commit.asset_id == locked_commitment.asset_id,
        "maker_change_commit asset_id should always match the locked_commitment asset_id",
    );
    if (inputs.auth_sig_pubkey.x == 0x00) {
        assert(
            inputs.actual_amount_recipient_commitments == 1,
            "Canceling a swaptoad trade can only create 1 new commitment",
        );
        assert(
            locked_commitment.owner_hash == inputs.owner_hash,
            "only owner can cancel a swaptoad trade",
        );
        // auth_sig_inputs set to zero? okay no signature was provided in private inputs of circuit.
        // that means that owner of the commitment want to cancel
        // they just want their money back so let's no ask them to verify their own signature and complete a trade
        // with them selfs!

        // we only need to nullify the locked commitment, but this always needs to happen, so happens after this if/else block
        // After this if/else block all after the second nullfier is nullified but not the second so let do that now
        taker_spend_nullfier =
            hash_fake_nullifier(inputs.spend_commitments_and_roots[1].shared_nonce);
        assert(
            maker_change_commit.amount == locked_commitment.amount,
            "amount in the first new commitment needs to match amount locked",
        );
        // rest of the commitments hashes made should be fake
        maker_new_commit_hash = hash_fake_commitment(inputs.recipient_commitments[1].shared_nonce);
        taker_change_commit_hash =
            hash_fake_commitment(inputs.recipient_commitments[2].shared_nonce);
        taker_new_commit_hash = hash_fake_commitment(inputs.recipient_commitments[3].shared_nonce);
    } else {
        assert(
            inputs.actual_amount_recipient_commitments == 4,
            "A swaptoad fill can only create 4 new real commitment, rest needs to be fake!!",
        );
        let taker_spend_commitment: ProvenCommitment = inputs.spend_commitments_and_roots[1];
        let signed_order: SwapToadOrder = SwapToadOrder {
            listing_asset_id: inputs.auth_sig_inputs[0],
            listing_amount: inputs.auth_sig_inputs[1],
            payment_asset_id: inputs.auth_sig_inputs[2],
            payment_amount: inputs.auth_sig_inputs[3],
            expiry: inputs.auth_sig_inputs[4],
            // TODO we need 2 messages, for maker_change_commit and taker_change_commit
            first_message_hash: inputs.auth_sig_inputs[5],
            maker_pre_commitment_hash: inputs.auth_sig_inputs[6],
        };

        assert(
            inputs.proof_expire_time_stamp.lt(signed_order.expiry),
            "Order expiry can not happen before the proof is expires.",
        );
        assert(
            maker_change_commit.pre_commitment_hash == signed_order.maker_pre_commitment_hash,
            "maker change commitment needs the specified maker_pre_commitment_hash from the signed swaptoad order",
        );
        assert(
            inputs.first_message_hash == signed_order.first_message_hash,
            "first_message_hash does not match makers required first_message_hash from auth_sig_inputs",
        );
        // check auth sig actually belongs to that in the locked commitment storage
        assert(
            lock_storage.auth == inputs.auth_sig_pubkey,
            "auth_pub_key.x does match the auth_pub_key_x from circuit_comp_storage in the locked_commitment",
        );
        // TODO can we join_split before settle?
        // @notice we need this order because signed data checks the first 2 message hashes (maybe technically not needed to match but would make things wierd for sdk?)
        let maker_new_commit: CommitmentRecipientData = inputs.recipient_commitments[1];
        let taker_change_commit: CommitmentRecipientData = inputs.recipient_commitments[2];
        let taker_new_commit: CommitmentRecipientData = inputs.recipient_commitments[3];

        // this is the only case we need owner_keys_hash from a commitment that is spend
        // join_split only checks owner_hash == owner_hash_from_main
        // we cant check against the one from main since that is taker. not maker
        // but now private inputs all have owner_keys_hash even tho we only need one
        // TODO optimize!!
        assert(
            locked_commitment.owner_hash
                == hash_owner(locked_commitment.owner_keys_hash, inputs.current_giga_index),
            "giga_index mismatch in locked commitment. This locked commitment can only be spend on it's one giga_index it has. And the correct owner_keys_hash of maker needs to be provided.",
        );

        // only one asset_id
        // don't get it mixed up!
        // maker sells asset_A for asset_B
        // if anything left over gets asset_A as change and asset_B as new commitment
        // new---
        assert(
            maker_new_commit.asset_id == signed_order.payment_asset_id,
            "maker_new_commit asset_id mismatch with asset_id in signed_order.payment_asset_id",
        );
        // taker is doing the filling, and he should not mess with makers change and swap out asset_ids!
        // before if/else block this is always checked with locked_commitment and locked_commitment is checked against signed order
        // assert(
        //     maker_change_commit.asset_id == signed_order.listing_asset_id,
        //     "maker_change_commit asset_id mismatch with asset_id in signed_order.listing_asset_id",
        // );
        assert(
            taker_change_commit.asset_id == signed_order.payment_asset_id,
            "taker_change_commit asset_id mismatch with asset_id in signed_order.payment_asset_id",
        );
        assert(
            taker_new_commit.asset_id == signed_order.listing_asset_id,
            "taker_new_commit asset_id mismatch with asset_id in signed_order.listing_asset_id",
        );

        //spend --
        assert(
            locked_commitment.asset_id == signed_order.listing_asset_id,
            "locked_commitment asset_id must match listing_asset_id of signed order",
        );
        assert(
            taker_spend_commitment.asset_id == signed_order.payment_asset_id,
            "taker_spend_commitment asset_id must match payment_asset_id of signed order",
        );
        assert(
            taker_spend_commitment.circuit_comp_selector == JOIN_SPLIT_SELECTOR,
            "Only a join split commitment can fill a trade with taker_spend_commitment",
        );

        // maker needs to be sure their new commiments build by taker are build properly
        // a mismatch like example circuit_comp_storage set to a random number maker does not know
        // and maker cant spend that commitment anymore!
        // check owner_hash of maker. Since taker is acting on makers behalve
        // taker can do what ever with thier commitments owner_hash

        // owner_hash
        assert(
            maker_new_commit.owner_hash == locked_commitment.owner_hash,
            "owner_hash needs to stay same for the maker_new_commit as the locked_commitment",
        );
        assert(
            maker_change_commit.owner_hash == locked_commitment.owner_hash,
            "owner_hash needs to stay same for the maker_change_commit as the locked_commitment",
        );

        // ciruit selector and storage
        assert(
            maker_new_commit.circuit_comp_input == std::mem::zeroed(),
            "circuit_comp_storage must be empty on maker commitments",
        );
        assert(
            maker_new_commit.circuit_comp_selector == JOIN_SPLIT_SELECTOR,
            "circuit_comp_selecto must be set to JOIN_SPLIT for maker commitments",
        );
        assert(
            maker_change_commit.circuit_comp_input == std::mem::zeroed(),
            "circuit_comp_storage must be empty on maker commitments",
        );
        assert(
            maker_change_commit.circuit_comp_selector == JOIN_SPLIT_SELECTOR,
            "circuit_comp_selecto must be set to JOIN_SPLIT for maker commitments",
        );

        // shared_nonce
        assert(
            maker_new_commit.shared_nonce
                == hash_shared_nonce_swaptoad(lock_storage.shared_nullifier_secret, 0),
            "shared_nonce has to be a hashed with hash_shared_nonce_swaptoad",
        );
        assert(
            maker_change_commit.shared_nonce
                == hash_shared_nonce_swaptoad(lock_storage.shared_nullifier_secret, 1),
            "shared_nonce has to be a hashed with hash_shared_nonce_swaptoad",
        );

        // amounts
        assert(
            maker_new_commit.amount == signed_order.payment_amount,
            "maker_new_commit.amount mismatch",
        );
        assert(
            taker_new_commit.amount == signed_order.listing_amount,
            "taker_new_commit.amount mismatch",
        );
        assert(
            maker_change_commit.amount == locked_commitment.amount - signed_order.listing_amount,
            "maker_change_commit.amount mismatch",
        );
        assert(
            taker_change_commit.amount
                == taker_spend_commitment.amount - signed_order.payment_amount,
            "taker_change_commit.amount mismatch",
        );

        // balance checks on the 2 commitments being spend
        assert(
            greater_or_equal(locked_commitment.amount, taker_new_commit.amount),
            "taker is taking more tokens then there are in the locked commitments",
        );
        assert(
            greater_or_equal(taker_spend_commitment.amount, maker_new_commit.amount),
            "maker is recieving more tokens then taker has in their taker_spend_commitment",
        );

        // locked_commitment was already checked above this if/else, since it is always spend
        // but takers spend still needs a check
        check_root(taker_spend_commitment, inputs, "taker_spend_commitment");
        assert(
            taker_spend_commitment.owner_hash == inputs.owner_hash,
            "taker_spend_commitment is not spendable with this owner_signature",
        );
        taker_spend_nullfier = hash_nullifier(
            inputs.nullifier_secret,
            taker_spend_commitment.giga_leaf_index,
            taker_spend_commitment.local_leaf_index,
        );

        // makers commitments are special, since taker is creating them on their behalve
        // so we alse check the pre_commitment!

        // TODO make this a function. "constrain_pre_commit()
        assert(
            maker_new_commit.pre_commitment_hash
                == hash_pre_commitment(
                    maker_new_commit.owner_hash,
                    maker_new_commit.shared_nonce,
                    maker_new_commit.circuit_comp_selector,
                    hash_circuit_component_storage(maker_new_commit.circuit_comp_input),
                ),
            "maker_new_commit.pre_commitment_hash mismath with hashed values on fill",
        );
        maker_new_commit_hash = hash_commitment(
            maker_new_commit.pre_commitment_hash,
            maker_new_commit.asset_id,
            maker_new_commit.amount,
        );
        taker_change_commit_hash = hash_commitment(
            taker_change_commit.pre_commitment_hash,
            taker_change_commit.asset_id,
            taker_change_commit.amount,
        );
        taker_new_commit_hash = hash_commitment(
            taker_new_commit.pre_commitment_hash,
            taker_new_commit.asset_id,
            taker_new_commit.amount,
        );
    }

    let maker_change_commit_hash: Field = hash_commitment(
        maker_change_commit.pre_commitment_hash,
        maker_change_commit.asset_id,
        maker_change_commit.amount,
    );
    assert(
        inputs.recipient_commitments_hashes[0] == maker_change_commit_hash,
        "maker_change_commit_hash mismatch",
    );
    assert(
        inputs.recipient_commitments_hashes[1] == maker_new_commit_hash,
        "maker_new_commit_hash mismatch",
    );
    assert(
        inputs.recipient_commitments_hashes[2] == taker_change_commit_hash,
        "taker_change_commit_hash mismatch",
    );
    assert(
        inputs.recipient_commitments_hashes[3] == taker_new_commit_hash,
        "taker_new_commit_hash mismatch",
    );

    // cancel or fill, locked_commitment always get's nullfied like this
    let shared_nullifier: Field = hash_nullifier(
        lock_storage.shared_nullifier_secret,
        locked_commitment.giga_leaf_index,
        locked_commitment.local_leaf_index,
    );
    assert(
        inputs.nullifiers[0] == shared_nullifier,
        "First nullifier needs to be hashed from the shared nullifier from circuit_comp_storage",
    );
    assert(
        inputs.nullifiers[1] == taker_spend_nullfier,
        "second nullfier does not match takers spend nullfier",
    );

    // we only ever nullify max 2 commitment, 1 if cancel, 2 if fill, the rest should be fake
    for i in 2..SIZE {
        let fake_nullifier: Field =
            hash_fake_nullifier(inputs.spend_commitments_and_roots[i].shared_nonce);
        assert(
            inputs.nullifiers[i] == fake_nullifier,
            "fake nullifier mismatch. All nullifiers after the first 2 need to be fake when canceling or filling swaptoad commitment",
        );
    }
}

// TODO dummy nullifiers and commitment_hashes
fn join_split<let SIZE: u32>(inputs: CircuitCompInputs<SIZE>) {
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
            // owner
            assert(
                spend_commitment.owner_hash == inputs.owner_hash,
                "Every spend commitment in join_split needs to have the owner_hash from the owner signature",
            );
            // other checks
            assert(
                spend_commitment.circuit_comp_selector == JOIN_SPLIT_SELECTOR,
                "The first commitment in spend_commitments was set to JOIN_SPLIT, but another was found set to a different circuit component. Please only spend from one circuit component at a time.",
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
            let recipient_circuit_comp_storage_hash: Field =
                hash_circuit_component_storage(recipient_commitment.circuit_comp_input);

            // This customizable check is dropped, when ever someone does shield() in warptoad.sol
            // They can put anything they want into pre_commitment_hash, including the storage hash
            // So checking these inputs here is useless if it can be bypassed anyway
            // We just need to assume anything can appear into storage like that and rely on asset_id and amount
            // For accounting / solvency
            // if (recipient_commitment.circuit_comp_selector == JOIN_SPLIT_SELECTOR) {
            //     recipient_storage_hash = hash_join_split_inputs(inputs)
            // } else {
            //     assert(
            //         false,
            //         "unknown circuit_comp_selector in recipient_commitments when trying to call a circuit component",
            //     );
            // };
            assert(
                expected_asset_id == recipient_commitment.asset_id,
                "recipient_commitments does not contain all same assetIds",
            );

            // track amounts
            spend += recipient_commitment.amount;
            // TODO this works right? Also spendable does need this right? If total supply is < FIELD_LIMIT?
            assert(lower_or_equal(recipient_commitment.amount, spend), "spend overflowed");

            // TODO hoist this out of here so other circuit components don't do double works hashing like this
            // and check here:
            // recipient_commitment_hash == inputs.recipient_commitments_hashes[index]
            // expected_asset_id == recipient_commitment.asset_id
            // recipient_storage_hash == recipient_commitment.circuit_comp_storage_hash
            // let pre_commitment_hash: Field = hash_pre_commitment(
            //     recipient_commitment.owner_hash,
            //     recipient_commitment.shared_nonce,
            //     // notice: circuit_comp selector/storage can be set to anything here
            //     recipient_commitment.circuit_comp_selector,
            //     recipient_circuit_comp_storage_hash,
            // );
            recipient_commitment_hash = hash_commitment(
                recipient_commitment.pre_commitment_hash,
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
