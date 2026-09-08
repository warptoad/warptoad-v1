mod merkle;
mod hashing;
mod constants;

use crate::merkle::{
    leaf_and_index_to_root, leaf_to_root, LeafAndIndexInclusionProof, LeafInclusionProof,
};

use crate::hashing::{
    hash_circuit_contract_auth_sig, hash_circuit_contract_storage, hash_commitment, hash_giga_leaf,
    hash_nullifier, hash_owner, hash_pre_commitment, hash_spend_signature_inputs,
};

use crate::constants::{
    CIRCUIT_CONTR_AUTH_SIZE, CIRCUIT_CONTR_STORAGE_EMPTY_HASH, CIRCUIT_CONTR_STORAGE_SIZE,
    CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH,
};
use eddsa::eddsa_verify;
use poseidon::{poseidon2::{self, Poseidon2}, poseidon::PoseidonHasher};
use std::string;

/**                                                            # sender needs to share everything in commitment + preCommitmentHash, so: [shared_nonce, CIRCUIT_CONTRACT, asset_id, amount]. maybe also share inputs of asset_id idk. We could store that one time onchain so the encrypted blob wont be huge. owner knows owner_hash inputs, he is literally him
 *   # is it okay that there is there is no domain separator?  /
 *   # everything else + which asset and how much             /                        giga_root             
 *   # note: contractAddr, amount are values in public,      /                        /         \
 *   # during shield/unshield. But not during shielded tx   /                   giga_leaf       other_giga_leaves
 *                                                   |     |                   /    |     \
 *                                                   |     | commitmentTreeRoot   local_   GIGA_LEAF_DOMAIN <- # without this you can confuse with a internal node
 *            # Who owns it + what controls it       |     |/       \             edge_index               \
 *                                |               commitment        otherLeafs..      |                     \
 * to refer to recipient          |              /     |    \                         |             # needed to verify leaf_index since we need it for the nullifier
 * without knowing                |             /      |     \
 * their chain or pubKey       preCommitmentHash    asset_id  amount <- erc20=amount,721=1, 1155=amount of that nft id     
 *         \                  /   |      \       \        \       
 *        ----owner_hash------  shared_  CIRCUIT_ \       erc20=keccak(contractAddr,0,originGigaIndex,"ERC20"),erc721=keccak(contractAddr,nftId,originGigaIndex,"ERC721"),erc1155=keccak(contractAddr,nftId,"ERC1155")
 *        / |       |        \   nonce   CONTRACT  \
 *       / /        |         \      |               circuit_contract_storage_hash
 *  spending  dest_giga_index  \   to blind commit                            |
 *   PubKey                     \                                         # ex in join_split: pre_nullifier
 *   X and y                   nullifier_secret                           # swap_lock: end_swap_pre_nullifier, timer_start_pre_nullifier, taker_timer_start_pre_nullifier.
 *                                   |                                    #   // taker_timer_start_pre_nullifier is to ensure, h(take_timer_pre_null, taker_null_secret) is not seen
 *                                   |                                    #   // basically it checks. Taker you better not start ur unlock timer while closing this trade. Or worse timer is already over and funds gone!
 *                                   |                                    # deferred_inclusion: pre_nullifier, deferred_root      
 *                       # derived from viewingKey (or somewhere else?)                                         
 *                       # re-used! nullifier(nullifier_secret, giga_index, leaf_index)    
 *                       # TODO if tree resets, so does index: but at that point a attack would need 
*/
fn proof_local_root_to_giga_root<let MAX_DEPTH: u32>(
    proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    giga_first_valid_index: Field,
    giga_last_valid_index: Field,
) -> Field {
    assert(
        lower_or_equal(proof.index, giga_first_valid_index),
        "gigaProof index below valid_giga_index_range",
    );
    assert(
        greater_or_equal(proof.index, giga_last_valid_index),
        "gigaProof index above valid_giga_index_range",
    );
    let giga_leaf: Field = hash_giga_leaf(local_root, local_edge_index);
    leaf_and_index_to_root(proof, giga_leaf, giga_edge_index)
}

fn proof_root_of_commitments<let MAX_DEPTH: u32, let SIZE: u32>(
    spend_commitments: [CommitmentSpendProof<MAX_DEPTH>; SIZE],
    local_root: Field,
    giga_edge_index: Field,
    giga_first_valid_index: Field,
    giga_last_valid_index: Field,
    owner_hash: Field,
    dest_giga_index: Field,
) -> [ProvenCommitment; SIZE] {
    let mut proven_commitments: [ProvenCommitment; SIZE] = std::mem::zeroed();
    for index in 0..SIZE {
        let spend_commitment: CommitmentSpendProof<MAX_DEPTH> = spend_commitments[index];
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
            giga_edge_index,
        );
        // this checks if proof is on same chain, in which case we skip giga_root checks
        if (proven_commitments[index].local_root == local_root) {
            // circuit contracts will get a 0x00 giga_root
            // proven_commitment.giga_root = 0x00;
            // no lying about the giga_index!
            proven_commitments[index].giga_leaf_index = dest_giga_index;
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
    }
    proven_commitments
}

fn verify_signature(spend_pub_key: PubKey, signature: Signature, sig_hash: Field) -> bool {
    eddsa_verify::<PoseidonHasher>(
        spend_pub_key.x,
        spend_pub_key.y,
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

// TODO remember to pad timestamps a bit, by just waiting a extra random amount of time. So not to finger print txs proof time
// TODO remember to domain separate fake nullifiers and commitments,
fn main(
    // root verify
    local_root: pub Field, // to short circuit and skip giga_root check
    local_edge_index: pub Field, // ^
    giga_root: pub Field, // verify spend commitment
    giga_edge_index: pub Field, // ^
    giga_first_valid_index: pub Field, // ^
    giga_last_valid_index: pub Field, // ^
    //timestamps: never possible the read the exact time rn, but with these 2 you can get a range
    proof_expire_time_stamp: pub Field,
    historic_time_stamp: pub Field,
    // owner data
    dest_giga_index: pub Field, // to verify owner is on this chains giga_index
    // call shit
    public_hash: pub Field, // anything done in public is in here, encrypted blobs, contract calls, etc, attached to spenders signature and constrained to proof shared to relayer
    // zk pub data
    nullifiers: pub [Field; CIRCUIT_SIZE], // to make `spend_commitments` un spendable
    recipient_commitments_hashes: pub [Field; CIRCUIT_SIZE], // for recipient to use to spend in next proof
    recipient_commitments: [CommitmentRecipientData; CIRCUIT_SIZE],
    // proof
    spend_commitments: [CommitmentSpendProof<MAX_TREE_DEPTH>; CIRCUIT_SIZE], // to proof owner owns things
    //signed_data: PrivateSignedData, // get rid of this. Just sign hash of all recipient_commitments + spend_commitments
    // bad actors can't use the signature to steal funds or nullify shit you didn't intend to nullify
    // add public_hash and withdraw address, contract calls, or abstracted accounts calls are now also solid
    // dont need timestamps, these are only used as source of truth not intent, same with root data
    // secret owner data
    spend_pub_key: PubKey, // who is spender
    nullifier_secret: Field, // how spender will derive nullifiers from
    spend_signature: Signature,
    // circuit contract call data
    auth_signature: Signature,
    auth_sig_inputs: [Field; CIRCUIT_CONTR_AUTH_SIZE],
    recipient_circuit_contr_selector: Field,
) {
    let owner_hash: Field = hash_owner(spend_pub_key, dest_giga_index, nullifier_secret);
    // @warning: THESE COMMITMENTS ARE NOT VERIFIED, only that commitment+proof = root, but THAT ROOT CAN BE INVALID
    // the `circuit_contract` functions below should check if those roots are valid!
    let spend_commitments_and_roots: [ProvenCommitment; CIRCUIT_SIZE] =
        // local_root is passed here, ONLY TO SKIP giga_root proof checks. IT IS NOT VERIFIED
        proof_root_of_commitments(
            spend_commitments,
            local_root,
            giga_edge_index,
            giga_first_valid_index,
            giga_last_valid_index,
            owner_hash,
            dest_giga_index,
        );

    let spend_sig_hash: Field = hash_spend_signature_inputs(
        public_hash,
        spend_commitments_and_roots,
        recipient_commitments_hashes,
    );
    assert(
        verify_signature(spend_pub_key, spend_signature, spend_sig_hash),
        "invalid spend signature",
    );

    let auth_sig_hash: Field = hash_circuit_contract_auth_sig(auth_sig_inputs);
    assert(
        verify_signature(spend_pub_key, spend_signature, auth_sig_hash),
        "invalid auth signature",
    );
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
    if (recipient_circuit_contr_selector == JOIN_SPLIT_SELECTOR) {
        // TODO nullifier = h(nullifier_secret, giga_index, local_index)
        // for commitment emitting multiple nullifiers like swap_maker_lock_contract needing closed_nullifier, timer_started_nullifier
        // just add a nullifier slot number
        join_split(
            CircuitContrInputs {
                local_root,
                giga_root,
                proof_expire_time_stamp,
                historic_time_stamp,
                public_hash,
                nullifiers,
                recipient_commitments_hashes,
                recipient_commitments,
                spend_commitments_and_roots,
                nullifier_secret,
                auth_sig_inputs,
                owner_hash,
            },
        )
    } else {

        //assert(false, "unknown signed_data.circuit_contract_selector");
    }
}

pub struct CircuitContrInputs<let SIZE: u32> {
    local_root: Field,
    giga_root: Field,
    proof_expire_time_stamp: Field,
    historic_time_stamp: Field,
    public_hash: Field, // here you can constrain what is done in public
    nullifiers: [Field; SIZE],
    recipient_commitments_hashes: [Field; SIZE],
    recipient_commitments: [CommitmentRecipientData; SIZE],
    spend_commitments_and_roots: [ProvenCommitment; SIZE],
    nullifier_secret: Field,
    auth_sig_inputs: [Field; CIRCUIT_CONTR_AUTH_SIZE],
    owner_hash: Field,
}

// this guy has no inputs!
fn hash_join_split_inputs<let SIZE: u32>(inputs: CircuitContrInputs<SIZE>) -> Field {
    CIRCUIT_CONTR_STORAGE_EMPTY_HASH
}

fn join_split<let SIZE: u32>(inputs: CircuitContrInputs<SIZE>) {
    // only one asset at the time pls
    let expected_asset_id: Field = inputs.spend_commitments_and_roots[0].asset_id;
    let mut spendable: Field = 0;
    let mut spend: Field = 0;
    for index in 0..SIZE {
        let spend_commitment = inputs.spend_commitments_and_roots[index];
        let recipient_commitment = inputs.recipient_commitments[index];
        // call another circuit contract. and get the storage_has
        let mut recipient_storage_hash: Field = CIRCUIT_CONTR_STORAGE_EMPTY_HASH;
        if (recipient_commitment.circuit_contr_selector == JOIN_SPLIT_SELECTOR) {
            recipient_storage_hash = hash_join_split_inputs(inputs)
        } else {
            assert(false, "unknown circuit_contr_selector in recipient_commitments when trying to call a circuit contract");
        };
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
        assert(
            expected_asset_id == spend_commitment.asset_id,
            "spend_commitments does not contain all same assetIds",
        );
        assert(
            expected_asset_id == recipient_commitment.asset_id,
            "recipient_commitments does not contain all same assetIds",
        );

        let nullifier: Field = hash_nullifier(
            inputs.nullifier_secret,
            spend_commitment.giga_leaf_index,
            spend_commitment.local_leaf_index,
        );
        assert(nullifier == inputs.nullifiers[index], "nullifier mismatch");

        // track amounts
        spendable += spend_commitment.amount;
        spend += recipient_commitment.amount;
        // TODO this works right? Also spendable does need this right? If total supply is < FIELD_LIMIT?
        assert(
            lower_or_equal(spend_commitment.amount, spend),
            "spend overflowed",
        );

        // TODO check that is chill that we basically call any other circuit_contract and not check its storage inputs
        // @notice this also check owner
        let pre_commitment_hash: Field = hash_pre_commitment(
            inputs.owner_hash,
            recipient_commitment.shared_nonce,
            recipient_commitment.circuit_contr_selector,
            recipient_storage_hash,
        );
        let recipient_commitment_hash: Field = hash_commitment(
            pre_commitment_hash,
            expected_asset_id,
            recipient_commitment.amount,
        );
        assert(
            recipient_commitment_hash == inputs.recipient_commitments_hashes[index],
            "a commitment_hash from public inputs does not match the recipient_commitment inputs hashed in circuit",
        );
    }
    assert(lower_or_equal(spend, spendable), "not enough funds");
}
