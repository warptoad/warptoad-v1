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
    CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH, NON_CIRCUIT_COMP_AUTH_INPUTS,
    SWAP_TOAD_ORDER_SIZE, SWAP_TOAD_SELECTOR,
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
            proven_commitments[index].owner_hash = spend_commitment.commitment.owner_hash
        } else {
            // it's a fake commitment so we make a fake_commitment hash
            // don't need this because this is not a commitment publicly inserted in the tree
            // proven_commitments[index].commitment_hash =
            //     hash_fake_commitment(spend_commitment.commitment.shared_nonce)
        }
        proven_commitments[index].shared_nonce = spend_commitment.commitment.shared_nonce;
        proven_commitments[index].unproven_owner_keys_hash =
            spend_commitment.commitment.owner_keys_hash;
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
    // TODO we can optimize by removing this and not hashing this in proof_root_of_commitments
    // and instead just pass 1 array of this through to circuit components that actually need it
    // like join_split does not need it, rest does. Saves `CIRUIT_SIZE - 1` hashes and private inputs
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
    //------------------------------
    //@TODO BEFORE PER TX NULLIFIER BRANCH remove `circuit_comp_selector, circuit_comp_input`
    // for now keep these to minimize breaking changes
    circuit_comp_selector: Field,
    circuit_comp_input: [Field; CIRCUIT_COMP_STORAGE_SIZE],
    //-----------------------
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
    // unproven since only swaptoad needs this.
    // TODO better place for this?
    unproven_owner_keys_hash: Field,
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
    message_hashes:[Field;SIZE] ,
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
    spend_selectors: [Field; SIZE],
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
    // will accept anything when `priv_in.auth.pub_key.x == 0x00`, but is okay, then it's just a selector
    let auth_selector: Field = priv_in.auth.inputs[0];
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
        message_hashes: pub_in.message_hashes,
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
    // --------------- circuit components ----------------
    // is okay, join_split takes over if auth_selector is set to anything unkown
    // assert(
    //     (auth_selector == SWAP_TOAD_SELECTOR) | (auth_selector == JOIN_SPLIT_SELECTOR),
    //     "unkown auth_selector",
    // );

    //
    for i in 0..CIRCUIT_SIZE {
        assert(
            (priv_in.spend_selectors[i] == SWAP_TOAD_SELECTOR)
                | (priv_in.spend_selectors[i] == JOIN_SPLIT_SELECTOR),
            "unkown spend_selector",
        );
    }
    join_split(circuit_comp_inputs, priv_in.spend_selectors, auth_selector);
    swaptoad(circuit_comp_inputs, priv_in.spend_selectors, auth_selector);
    // --------------- ------------------ ----------------
    // @WARNING CONTAINS UNCONSTRAINT CODE
    // TODO remove all unconstraint code and instead just put hints like that in the priv_inputs
    check_accounting(
        circuit_comp_inputs.recipient_commitments,
        // circuit components can modify this incase of minting / creating new asset_ids / if accounting already checked somehow
        // but caller needs to be forced to leave those recipient commitments last
        circuit_comp_inputs.actual_amount_recipient_commitments,
        circuit_comp_inputs.spend_commitments_and_roots,
        // no need to modify this one. Larger totals are harmless in anycase (AFAIK)
        // i dont see a circuit component reading a commitment and then that thing tripping up account somehow? Nah
        circuit_comp_inputs.actual_amount_spend_commitments,
    );

    // @WARNING every circuit component should either block unshield by doing assert(unshielding_commitment.asset_id == 0x00)
    // or correctly check accounting on these unshielding_commitments
    for i in 0..CIRCUIT_SIZE {
        let spend_commit: ProvenCommitment = circuit_comp_inputs.spend_commitments_and_roots[i];
        let unshielding_commitment: UnshieldingCommitment = pub_in.unshielding_commitments[i];
        let recipient_commitment: CommitmentRecipientData = priv_in.recipient_commitments[i];
        let commit_hash: Field = pub_in.recipient_commitments_hashes[i];
        let nullfier: Field = pub_in.nullifiers[i];

        if (i < priv_in.actual_amount_spend_commitments) {
            // if a unkown selector is used, then that spend is never checked and cause infinite mint
            assert(
                (spend_commit.circuit_comp_selector == JOIN_SPLIT_SELECTOR)
                    | (spend_commit.circuit_comp_selector == SWAP_TOAD_SELECTOR),
                "spend commitment has a unknown circuit_comp_selector",
            );
            // circuit components still customized this
            // TODO AT PER TX NULLIFIER BRANCH, do hashing here to save on constraints
        } else {
            assert(
                nullfier == hash_fake_nullifier(spend_commit.shared_nonce),
                "fake commitment hash mismatch",
            );
        }

        // only non fakes can unshield so only those get the asserts of:
        // unshielding_commitment.thing == recipient_commitment.thing
        if (i < priv_in.actual_amount_recipient_commitments) {
            assert(
                pub_in.recipient_commitments_hashes[i]
                    == hash_commitment(
                        recipient_commitment.pre_commitment_hash,
                        recipient_commitment.asset_id,
                        recipient_commitment.amount,
                    ),
                "recipient_commitments_hashes misatch",
            );
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
            // fake is still fake!! so let's make sure we never mix that up for the commitment hash and nullifier!!
            // TODO his hash operation can be optimized so it shares a operation with a real hash, just constrain different inputs to distinguish it from a fake
            assert(
                commit_hash == hash_fake_commitment(recipient_commitment.shared_nonce),
                "fake commitment hash mismatch",
            );
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
    message_hashes: [Field; SIZE],
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

pub struct SwapToadOrderOffsets {
    maker_new_commit: u32,
    maker_spend_commit: u32,
    message_hashes: u32,
    expiry: u32,
}
pub global SWAPTOAD_ORDER_OFFSETS: SwapToadOrderOffsets = SwapToadOrderOffsets {
    maker_new_commit: NON_CIRCUIT_COMP_AUTH_INPUTS,
    maker_spend_commit: NON_CIRCUIT_COMP_AUTH_INPUTS + SWAP_TOAD_ORDER_SIZE * 1,
    message_hashes: NON_CIRCUIT_COMP_AUTH_INPUTS + SWAP_TOAD_ORDER_SIZE * 2,
    expiry: NON_CIRCUIT_COMP_AUTH_INPUTS + SWAP_TOAD_ORDER_SIZE * 3,
};
pub struct PubKeyOffSets {
    x: u32,
    y: u32,
}

pub struct SwapToadStorageOffsets {
    pub_key: PubKeyOffSets,
    auth_expiry: u32,
    shared_nullifier_secret: u32,
}

pub global SWAPTOAD_STORAGE_OFFSETS: SwapToadStorageOffsets = SwapToadStorageOffsets {
    pub_key: PubKeyOffSets { x: 0, y: 1 },
    auth_expiry: 2,
    shared_nullifier_secret: 3,
};

fn check_root<let STRING_SIZE: u32>(
    commitment: ProvenCommitment,
    local_root: Field,
    giga_root: Field,
    // just for debug
    commitment_name: str<STRING_SIZE>,
) {
    if commitment.giga_root == 0 {
        assert(
            commitment.local_root == local_root,
            f"commitment: {commitment_name} spend was local only but does not match local_root from public inputs",
        );
    } else {
        assert(
            commitment.giga_root == giga_root,
            f"commitment: {commitment_name} spend was *not* local and does not match giga_root from public inputs",
        );
    }
}

fn swaptoad<let SIZE: u32>(
    inputs: CircuitCompInputs<SIZE>,
    spend_selectors: [Field; SIZE],
    auth_selector: Field,
) {
    // swaptoad sleeps if SWAP_TOAD_SELECTOR was never in the auth_sig
    // TODO decide if a SWAP_TOAD_SELECTOR is also used for atomic swap
    // so user can be like: i can swap my commitment crosschain or samechain
    // without having to decide before they put their shit in a commitment
    if (auth_selector == SWAP_TOAD_SELECTOR) {
        assert(
            inputs.proof_expire_time_stamp.lt(inputs.auth_sig_inputs[SWAPTOAD_ORDER_OFFSETS.expiry]),
            "`proof_expire_time_stamp` needs to be before a swaptoads order expiry",
        );
        assert(inputs.auth_sig_pubkey.x != 0x00, "swaptoad needs an auth signature");
        for i in 0..SWAP_TOAD_ORDER_SIZE {
            // ----spend commit check --------
            let maker_spend_commit: Field =
                inputs.auth_sig_inputs[SWAPTOAD_ORDER_OFFSETS.maker_spend_commit + i];
            if (spend_selectors[i] == SWAP_TOAD_SELECTOR) {
                assert(
                    (inputs.actual_amount_spend_commitments > i),
                    "maker needs to nullify more spend commitments then actual_amount_spend_commitments allows",
                );
                let in_maker_spend_commit: ProvenCommitment = inputs.spend_commitments_and_roots[i];
                assert(
                    in_maker_spend_commit.giga_leaf_index == inputs.current_giga_index,
                    "wrong chain, cannot fill this trade here",
                );
                //
                assert(
                    in_maker_spend_commit.circuit_comp_selector == SWAP_TOAD_SELECTOR,
                    "only commitments with JOIN_SPLIT_SELECTOR can be used to fill a trade",
                );
                check_root(
                    in_maker_spend_commit,
                    inputs.local_root,
                    inputs.giga_root,
                    "[TOADSWAP] in_maker_spend_commit",
                );
                let nullifier: Field = hash_nullifier(
                    in_maker_spend_commit.circuit_comp_storage[SWAPTOAD_STORAGE_OFFSETS
                        .shared_nullifier_secret],
                    in_maker_spend_commit.shared_nonce,
                    in_maker_spend_commit.giga_leaf_index,
                    in_maker_spend_commit.local_leaf_index,
                );
                let owner_hash: Field = hash_owner(
                    in_maker_spend_commit.unproven_owner_keys_hash,
                    in_maker_spend_commit.giga_leaf_index,
                );
                assert(
                    in_maker_spend_commit.owner_hash == owner_hash,
                    "owner hash mismatch on swaptoad maker commitment",
                );
                assert(nullifier == inputs.nullifiers[i], "nullifier mismatch");
                assert(
                    (maker_spend_commit == in_maker_spend_commit.commitment_hash),
                    "expected maker_spend_commit hash does not line up with in_spend_commit_hash in private inputs",
                );
                let pub_key_storage: PubKey = PubKey {
                    x: in_maker_spend_commit.circuit_comp_storage[SWAPTOAD_STORAGE_OFFSETS.pub_key.x
                        ],
                    y: in_maker_spend_commit.circuit_comp_storage[SWAPTOAD_STORAGE_OFFSETS.pub_key.y
                        ],
                };
                // both spend and auth key usually are at the same security level. Like inside a hardware wallet
                // but offchain order ux is simply more prone to user error, so giving wallet and users to tools
                // to mitigate this issue by simply expiring the ability to sign offchain orders is added here.
                // so bored apes users can somewhat more securely use swaptoad :D
                let commit_auth_expiry: Field = in_maker_spend_commit.circuit_comp_storage[
                    SWAPTOAD_STORAGE_OFFSETS
                        .auth_expiry];
                assert(
                    lower_or_equal(inputs.proof_expire_time_stamp, commit_auth_expiry),
                    "`proof_expire_time_stamp` needs to be before the maker orders spend commitments auth expiry inside the circuit component storage",
                );
                assert(inputs.auth_sig_pubkey == pub_key_storage, "invalid auth pubkey");
            } else {
                assert(
                    maker_spend_commit == 0x00,
                    "maker_spend_commit from swaptoad order at ${i} expected the spend_selector to be set to SWAP_TOAD_SELECTOR",
                );
            }
            // --- new_commit check ---
            let maker_new_commit: Field =
                inputs.auth_sig_inputs[SWAPTOAD_ORDER_OFFSETS.maker_new_commit + i];
            if (maker_new_commit != 0x00) {
                let in_new_commit_hash: Field = inputs.recipient_commitments_hashes[i];
                assert(
                    (maker_new_commit == in_new_commit_hash),
                    "expected maker_new_commit hash does not line up with new_commit_hashes in public inputs",
                );
                assert(
                    inputs.unshielding_commitments[i].asset_id == 0x00,
                    "maker commitments cannot unshield",
                );

                // ---- message check (from new commit) ----
                // TODO do:
                // let in_message_hash: Field = inputs.message_hashes[i];
                let in_message_hash: Field = inputs.message_hashes[i];
                let order_message_hash: Field =
                    inputs.auth_sig_inputs[SWAPTOAD_ORDER_OFFSETS.message_hashes + i];
                assert(
                    (order_message_hash == in_message_hash),
                    "expected order_message_hash hash does not line up with message_hashes in public inputs",
                );
            }
            //--------------------------
        }
        // loop above does not go down to every spend commitment.
        // so we ensure here that another circuit component takes care of those
        for i in SWAP_TOAD_ORDER_SIZE..SIZE {
            assert(
                spend_selectors[i] != SWAP_TOAD_SELECTOR,
                "spend selectors out side of the swaptoad order cannot be SWAP_TOAD_SELECTOR",
            );
        }
    } else {
        for i in 0..SIZE {
            assert(
                spend_selectors[i] != SWAP_TOAD_SELECTOR,
                "spend selectors cannot be set to SWAP_TOAD_SELECTOR when auth selector is not SWAP_TOAD_SELECTOR",
            );
        }
    }
}

// makes a array of indexes that point the same asset_id to the same index.
// so [a,c,a,b] -> [0,1,0,3]
// notice that "b" ends up at index 3 not 2. that is becuase the function matches up
// with the first occurance of that asset_id in the original order
// so you also get ur total in `check_accounting` to be [a,c,nothing,b]
// @TODO remove this and make the inputs provide these hints
// i dont like unconstraint functions the scare me :/
unconstrained fn get_totals_indexes<let SIZE: u32>(
    spend_commitments: [ProvenCommitment; SIZE],
    actual_amount_spend_commitments: u32,
    recipient_commitments: [CommitmentRecipientData; SIZE],
    actual_amount_recipient_commitments: u32,
) -> ([u32; SIZE], [u32; SIZE]) {
    let mut s_indexes: [u32; SIZE] = std::mem::zeroed();
    let mut r_indexes: [u32; SIZE] = std::mem::zeroed();
    //
    for i in 0..actual_amount_spend_commitments {
        for j in 0..actual_amount_spend_commitments {
            if (spend_commitments[j].asset_id == spend_commitments[i].asset_id) {
                s_indexes[i] = j;
                break;
            }
        }
    }
    for i in 0..actual_amount_recipient_commitments {
        for j in 0..actual_amount_spend_commitments {
            if (spend_commitments[j].asset_id == recipient_commitments[i].asset_id) {
                r_indexes[i] = j;
                break;
            }
        }
    }
    (s_indexes, r_indexes)
}

// TODO naming
// but bassically this guy checks:
// spend_commitments are spend. And amounts on new recipients_commitments add up
// then later join_split can check if owner owns those commitments
// same toadswap, but either checks owner can cancel or taker has sig,
// bassically circuit contracts can costumize how they check preCommitHash and ownerhash
// and some also want to do that for the new recipient commitments being created (like toadswap!)
fn check_accounting<let SIZE: u32>(
    recipient_commitments: [CommitmentRecipientData; SIZE],
    actual_amount_recipient_commitments: u32,
    spend_commitments_and_roots: [ProvenCommitment; SIZE],
    actual_amount_spend_commitments: u32,
) {
    // @Safety: we let prover dump commitments in any order. And then use a unconstraint function to get the indexes of both
    let (s_indexes, r_indexes) = unsafe {
        get_totals_indexes(
            spend_commitments_and_roots,
            actual_amount_spend_commitments,
            recipient_commitments,
            actual_amount_recipient_commitments,
        )
    };
    // seed asset_ids before the loop so we dont have to check asset_ids[i] == 0x00
    // also needs to be done here and not in loop below
    // since r/s_indexes point forward and check asset_ids before it is filled
    let mut asset_ids: [Field; SIZE] = std::mem::zeroed();
    for i in 0..SIZE {
        asset_ids[i] = spend_commitments_and_roots[i].asset_id;
    }
    let mut spendable: [Field; SIZE] = std::mem::zeroed();
    let mut spend: [Field; SIZE] = std::mem::zeroed();
    for i in 0..SIZE {
        if (i < actual_amount_spend_commitments) {
            let total_index: u32 = s_indexes[i];
            assert(
                total_index < actual_amount_spend_commitments,
                "total index points at a fake spend commitment",
            );
            let s_commit: ProvenCommitment = spend_commitments_and_roots[i];
            assert(
                asset_ids[total_index] == s_commit.asset_id,
                "get_totals_indexes provided a asset_id mismatch",
            );
            spendable[total_index] += s_commit.amount;
        }

        if (i < actual_amount_recipient_commitments) {
            let total_index: u32 = r_indexes[i];
            // a total is always from a spend commitment, so this is compared to the amount of spend commitments
            assert(
                total_index < actual_amount_spend_commitments,
                "total index points at a fake spend commitment",
            );
            let r_commit: CommitmentRecipientData = recipient_commitments[i];
            // this also fails when the asset_id of this recipient commitment is not being spend at all
            // since then there is no total that has it's asset_id
            assert(
                asset_ids[total_index] == r_commit.asset_id,
                "get_totals_indexes provided a asset_id mismatch",
            );
            spend[total_index] += r_commit.amount;

            assert(lower_or_equal(r_commit.amount, spend[total_index]), "spend overflowed");
        }
    }
    for i in 0..SIZE {
        assert(spend[i] == spendable[i], "spend and spendable need to add up exactly");
    }
}

// TODO dummy nullifiers and commitment_hashes
fn join_split<let SIZE: u32>(
    inputs: CircuitCompInputs<SIZE>,
    spend_selectors: [Field; SIZE],
    // join_split does not care about auth
    auth_selector: Field,
) {
    for i in 0..SIZE {
        // ----------- spend commitment --------------------------
        // join_split wakes up only if spend_selector said so.
        if (
            // swaptoad is in here. So you can cancel a trade just by spending it
            (spend_selectors[i] == JOIN_SPLIT_SELECTOR)
                & (i < inputs.actual_amount_spend_commitments)
        ) {
            let spend_commitment: ProvenCommitment = inputs.spend_commitments_and_roots[i];
            check_root(
                spend_commitment,
                inputs.local_root,
                inputs.giga_root,
                "[JOIN_SPLIT] spend_commitment",
            );
            // owner (typicaly costumized by circuit components)
            assert(
                spend_commitment.owner_hash == inputs.owner_hash,
                "Every spend commitment in join_split needs to have the owner_hash from the owner signature",
            );
            // assert(
            //     spend_commitment.circuit_comp_selector == spend_selectors[i],
            //     "can't spend this commitment",
            // );

            // nullifier (typicaly customized by circuit components)
            // swaptoad re-uses join_split for cancels. But it derives it differently so we do:
            let nullifier_secret: Field = if (
                spend_commitment.circuit_comp_selector == SWAP_TOAD_SELECTOR
            ) {
                spend_commitment.circuit_comp_storage[SWAPTOAD_STORAGE_OFFSETS
                    .shared_nullifier_secret]
            } else if (spend_commitment.circuit_comp_selector == JOIN_SPLIT_SELECTOR) {
                inputs.nullifier_secret
            } else {
                assert(false, "spend_commitment ${i} contains unrecognized circuit_comp_selector");
                0x00
            };
            let nullifier: Field = hash_nullifier(
                nullifier_secret,
                spend_commitment.shared_nonce,
                spend_commitment.giga_leaf_index,
                spend_commitment.local_leaf_index,
            );
            assert(nullifier == inputs.nullifiers[i], "nullifier mismatch");
        }
    }
}
