mod merkle;

use crate::merkle::{
    leaf_and_index_to_root, leaf_to_root, LeafAndIndexInclusionProof, LeafInclusionProof,
};
use eddsa::eddsa_verify;
use poseidon::{poseidon2::{self, Poseidon2}, poseidon::PoseidonHasher};
use std::string;

// toHex("GIGA_LEAF", {size:32})
global GIGA_LEAF_DOMAIN: Field = 0x0000000000000000000000000000000000000000000000474947415f4c454146;

global CIRCUIT_SIZE: u32 = 6;
// to match aztec note_hash_tree, also we need to put edge index at 2**40 - 1 there
// no tree resets: at ~12M leaves/day 2^40 lasts ~250 years, quantum breaks bn254 first
global MAX_TREE_DEPTH: u32 = 40;
//   let unPadded = [...new TextEncoder().encode("JOIN_SPLIT")].map(b=>b.toString(16));
//     "0x" + [...new Array(32-unPadded.length).fill("00"), ...unPadded].join("");
global JOIN_SPLIT_SELECTOR: Field =
    0x000000000000000000000000000000000000000000004a4f494e5f53504c4954;

global JOIN_SPLIT_NULLIFIER_SLOT: Field = 0x00;
global SWAP_NULLIFIER_SLOT: Field = 0x00;
global SWAP_TIMER_NULLIFIER_SLOT: Field = 0x01;

// no branded types so we do the .inner convention
// aztec does it like that as well
pub struct OwnerHash {
    inner: Field,
}

// h(BlindedRecipientHash, circuit_contract_DOMAIN)
// who owns this and inside what circuit_contract
pub struct PreCommitmentHash {
    inner: Field,
}

pub struct CommitmentHash {
    inner: Field,
}

pub struct CommitmentLeafHash {
    inner: Field,
}

pub struct PubKey {
    x: Field,
    y: Field,
}

pub struct Signature {
    x: Field,
    y: Field,
    scalar: Field,
}

pub struct OwnerData {
    spending_key: PubKey,
    dest_giga_index: Field,
    // derived from owner private viewing key, only owner needs to know this nonce
    nullifier_secret: Field,
}

pub struct PrivateSignedData {
    circuit_contract_selector: Field,
    // contract address in erc20, keccak(contractAddress, id)[0:31] in erc1155 and erc721
    contract_address: Field,
    // amount in erc20 and erc1155. (always 1 in erc721)
    amount: Field,
    // which spending pubKey + circuit_contract_storage_hash can spend the funds
    recipient_owner_hash: OwnerHash,
    // no one needs to see this
    signature: Signature,
    // made by sender and shared with recipient for the tx that this circuit proofs
    new_shared_nonce: Field,
}

pub struct SignedData {
    private: PrivateSignedData,
    // hash of example amount to unshield, calldata, fee parameters
    // anything you might want to reveal to the public
    public_hash: Field,
    // also don't forget! include the encrypted blob in public_hash otherwise relayers can rug ur recipient and not give them the encrypted data they need
    //
    // just dumping here for now but full list of public shit that zktranswarp already needed
    // struct FeeData {
    //     uint256 tokensPerEthPrice;
    //     uint256 maxFee;
    //     uint256 amountForRecipient;
    //     uint256 relayerBonus;
    //     uint256 estimatedGasCost;
    //     uint256 estimatedPriorityFee;
    //     address refundAddress;
    //     address relayerAddress;
    // }
    // bytes callData;
    // bool callCanFail;
    // uint256 callValue; eth!
}

fn hash_signature_inputs(data: SignedData) -> Field {
    Poseidon2::hash(
        [
            data.private.contract_address,
            data.private.amount,
            data.private.recipient_owner_hash.inner,
            data.public_hash,
        ],
        4,
    )
}

fn hash_owner_data(owner_data: OwnerData) -> OwnerHash {
    // DECISION (2026-08-31): hash BOTH x and y. x-only is sound with noir eddsa
    // (it asserts on-curve + clears cofactor via *8), but circomlib's
    // EdDSAPoseidonVerifier does NO curve check on Ax/Ay — with x-only, y would be
    // a free witness there. Binding the full point here removes that dependency.
    // (When porting: still add BabyCheck on A and R8 in the circom verifier.)
    OwnerHash {
        inner: Poseidon2::hash(
            [
                owner_data.spending_key.x,
                owner_data.spending_key.y,
                owner_data.dest_giga_index,
                owner_data.nullifier_secret,
            ],
            4,
        ),
    }
}

fn hash_pre_commitment(
    owner_hash: OwnerHash,
    shared_nonce: Field,
    circuit_contract: Field,
    circuit_contract_storage_hash: Field,
) -> PreCommitmentHash {
    PreCommitmentHash {
        inner: Poseidon2::hash(
            [owner_hash.inner, shared_nonce, circuit_contract, circuit_contract_storage_hash],
            4,
        ),
    }
}
fn hash_commitment(
    pre_commitment_hash: PreCommitmentHash,
    contract_address: Field,
    amount: Field,
) -> CommitmentHash {
    CommitmentHash {
        inner: Poseidon2::hash([pre_commitment_hash.inner, contract_address, amount], 3),
    }
}

fn hash_commitment_leaf(commitment: CommitmentHash, asset_type: Field) -> CommitmentLeafHash {
    CommitmentLeafHash { inner: Poseidon2::hash([commitment.inner, asset_type], 2) }
}

struct CommitmentData {
    owner_data: OwnerData,
    // generated by sender, shared to recipient, not seen by public
    shared_nonce: Field,
    circuit_contract: Field,
    circuit_contract_storage_hash: Field,
    contract_address: Field,
    amount: Field,
    asset_type: Field,
}

struct CommitmentDataInclusion<let MAX_DEPTH: u32> {
    commitmentData: CommitmentData,
    local_proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    giga_proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_edge_index: Field,
}


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
fn hash_commitment_data(data: CommitmentData) -> CommitmentLeafHash {
    let owner_hash: OwnerHash = hash_owner_data(data.owner_data);
    //let circuit_contract_storage_hash = hash_circuit_contract_storage();
    assert(false, "storage hash is still set to 0 retard");
    let pre_commitment_hash: PreCommitmentHash =
        hash_pre_commitment(owner_hash, data.shared_nonce, data.circuit_contract, 0);
    let commitment: CommitmentHash =
        hash_commitment(pre_commitment_hash, data.contract_address, data.amount);
    hash_commitment_leaf(commitment, data.asset_type)
}

fn proof_commitment_to_local_root<let MAX_DEPTH: u32>(
    data: CommitmentDataInclusion<MAX_DEPTH>,
) -> Field {
    let commitment_leaf: CommitmentLeafHash = hash_commitment_data(data.commitmentData);
    leaf_and_index_to_root(
        data.local_proof,
        commitment_leaf.inner,
        data.local_edge_index,
    )
}

fn hash_giga_leaf(local_root: Field, local_edge_index: Field) -> Field {
    Poseidon2::hash([local_root, local_edge_index, GIGA_LEAF_DOMAIN], 3)
}

fn proof_local_root_to_giga_root<let MAX_DEPTH: u32>(
    proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    valid_giga_index_range: GigaIndexRange,
) -> Field {
    assert(
        lower_or_equal(proof.index, valid_giga_index_range.start),
        "gigaProof index below valid_giga_index_range",
    );
    assert(
        greater_or_equal(proof.index, valid_giga_index_range.end),
        "gigaProof index above valid_giga_index_range",
    );
    let giga_leaf = hash_giga_leaf(local_root, local_edge_index);
    leaf_and_index_to_root(proof, giga_leaf, giga_edge_index)
}

struct VerifiedCommitmentData {
    commitment: CommitmentData,
    local_root: Field,
    local_index: Field,
    local_edge_index: Field,
    giga_root: Field,
    giga_index: Field,
}
fn proof_root_of_commitments<let SIZE: u32>(
    commitment_proofs: [CommitmentDataInclusion<MAX_TREE_DEPTH>; SIZE],
    local_root: Field,
    local_edge_index: Field,
    giga_edge_index: Field,
    valid_giga_index_range: GigaIndexRange,
    dest_giga_index: Field,
) -> [VerifiedCommitmentData; SIZE] {
    let mut verified: [VerifiedCommitmentData; SIZE] = std::mem::zeroed();
    for index in 0..SIZE {
        // local
        verified[index].local_root = proof_commitment_to_local_root(commitment_proofs[index]);
        verified[index].local_index = commitment_proofs[index].local_proof.index;
        verified[index].commitment = commitment_proofs[index].commitmentData;

        // giga
        // contract handed us `local_root` and if that matches our reproduced commit_local_root, we don't need to check the giga_root proof
        // this so the caller can just put all zeros in the giga_root proof
        if (verified[index].local_root != local_root) {
            verified[index].giga_root = proof_local_root_to_giga_root(
                commitment_proofs[index].giga_proof,
                verified[index].local_root,
                commitment_proofs[index].local_edge_index,
                giga_edge_index,
                valid_giga_index_range,
            );
            verified[index].giga_index = commitment_proofs[index].giga_proof.index;
            verified[index].local_edge_index = commitment_proofs[index].local_edge_index;
        } else {
            // no verifying the gigaProof, hand me zeros if you want.
            // but no lying about your gigaIndex and local_edge_index! we use that for nullifiers to protect against faeries with fake gold!!
            verified[index].giga_root = 0x00;
            verified[index].giga_index = dest_giga_index;
            verified[index].local_edge_index = local_edge_index;
        };
    }
    verified
}
fn verify_signature(owner_secrets: OwnerData, signature: Signature, sig_hash: Field) -> bool {
    eddsa_verify::<PoseidonHasher>(
        owner_secrets.spending_key.x,
        owner_secrets.spending_key.y,
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

struct GigaIndexRange {
    // inclusive
    start: Field,
    // inclusive
    end: Field,
    //the check is: i >= start && i < end
}

// TODO remember to pad timestamps a bit, by just waiting a extra random amount of time. So not to finger print txs proof time
// TODO remember to domain separate fake nullifiers and commitments,
fn main(
    // never possible the read the exact time rn, but with these 2 you can get a range
    proof_expire_time_stamp: pub Field,
    historic_time_stamp: pub Field,
    dest_giga_index: pub Field,
    local_root: pub Field,
    local_edge_index: pub Field,
    giga_root: pub Field,
    giga_edge_index: pub Field,
    public_hash: pub Field,
    nullifiers: pub [Field; CIRCUIT_SIZE],
    new_commitments: pub [Field; CIRCUIT_SIZE],
    valid_giga_index_range: pub GigaIndexRange,
    spend_commitments: [CommitmentDataInclusion<MAX_TREE_DEPTH>; CIRCUIT_SIZE],
    spending_key: PubKey,
    signed_data: PrivateSignedData,
    nullifier_secret: Field,
) {
    let owner_data: OwnerData = OwnerData {
        spending_key: spending_key,
        dest_giga_index: dest_giga_index,
        nullifier_secret: nullifier_secret,
    };
    let sig_hash: Field = hash_signature_inputs(
        SignedData { private: signed_data, public_hash: public_hash },
    );
    assert(verify_signature(owner_data, signed_data.signature, sig_hash), "invalid signature");
    // @warning: THESE COMMITMENTS ARE NOT VERIFIED, only that commitment+proof = root, but THAT ROOT CAN BE INVALID
    // the `circuit_contract` functions below should check if those roots are valid!
    let spend_commitments_and_roots: [VerifiedCommitmentData; CIRCUIT_SIZE] =
        // local_root is passed here, ONLY TO SKIP giga_root proof checks. IT IS NOT VERIFIED
        proof_root_of_commitments(
            spend_commitments,
            local_root,
            local_edge_index,
            giga_edge_index,
            valid_giga_index_range,
            dest_giga_index,
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
    if (signed_data.circuit_contract_selector == JOIN_SPLIT_SELECTOR) {
        // TODO nullifier = h(nullifier_secret, giga_index, local_index)
        // for commitment emitting multiple nullifiers like swap_maker_lock_contract needing closed_nullifier, timer_started_nullifier
        // just add a nullifier slot number
        // join_split(nullifiers, new_commitments, spend_commitments);
    } else {

        //assert(false, "unknown signed_data.circuit_contract_selector");
    }
}

fn join_split(
    local_root: Field,
    giga_root: Field,
    public_hash: Field,
    nullifiers: [Field; CIRCUIT_SIZE],
    new_commitments: [Field; CIRCUIT_SIZE],
    spend_commitments: [VerifiedCommitmentData; CIRCUIT_SIZE],
    address_secrets: OwnerData,
    signed_data: PrivateSignedData,
) {}
