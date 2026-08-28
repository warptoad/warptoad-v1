mod merkle;

use crate::merkle::{leaf_to_root, LeafInclusionProof};
use eddsa::eddsa_verify;
use poseidon::{poseidon2::Poseidon2, poseidon::PoseidonHasher};

global CIRCUIT_SIZE: u32 = 4;
global MAX_TREE_DEPTH: u32 = 32;

pub struct PubKey {
    x: Field,
    y: Field,
}

pub struct Signature {
    x: Field,
    y: Field,
    scalar: Field,
}

pub struct BlindedRecipient {
    spending_key: PubKey,
    destination_warp_domain: Field,
    // derived from viewing key
    nonce: Field,
}

// no branded types so we do the .inner convention
// aztec does it like that as well
pub struct BlindedRecipientHash {
    inner: Field,
}

// h(BlindedRecipientHash, PROTOCOL_CONTRACT_DOMAIN)
// who owns this and inside what PROTOCOL_CONTRACT
pub struct OwnerHash {
    inner: Field,
}

pub struct CommitmentHash {
    inner: Field,
}

pub struct CommitmentLeafHash {
    inner: Field,
}

pub struct PrivateSignedData {
    // contract address in erc20, keccak(contractAddress, id)[0:31] in erc1155 and erc721
    contract_address: Field,
    // amount in erc20 and erc1155. (always 1 in erc721)
    amount: Field,
    // which spending pubKey + warp_domain can spend the funds
    owner_hash: BlindedRecipientHash,
    // no one needs to see this
    sig: Signature,
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
            data.private.owner_hash.inner,
            data.public_hash,
        ],
        4,
    )
}

fn hash_blinded_recipient(owner_data: BlindedRecipient) -> BlindedRecipientHash {
    // TODO we could only do .x? At-least on grumpkin (short Weierstrass ) thats okay
    // but we got jubjub (twisted edwards)
    BlindedRecipientHash {
        inner: Poseidon2::hash(
            [
                owner_data.spending_key.x,
                owner_data.spending_key.y,
                owner_data.destination_warp_domain,
                owner_data.nonce,
            ],
            4,
        ),
    }
}

fn hash_owner(recipient_hash: BlindedRecipientHash, protocol_contract: Field) -> OwnerHash {
    OwnerHash { inner: Poseidon2::hash([recipient_hash.inner, protocol_contract], 2) }
}

fn verify(pub_key: PubKey, sig: Signature, message: Field) -> bool {
    // eddsa_verify (aka baby jub jub) signing + poseidon already exists in circom
    // so we do that instead of poseidon2 to make switching easier.
    eddsa_verify::<PoseidonHasher>(pub_key.x, pub_key.y, sig.scalar, sig.x, sig.y, message)
}

fn hash_commitment(
    owner_hash: OwnerHash,
    contract_address: Field,
    amount: Field,
) -> CommitmentHash {
    CommitmentHash { inner: Poseidon2::hash([owner_hash.inner, contract_address, amount], 3) }
}

fn hash_commitment_leaf(commitment: CommitmentHash, asset_type: Field) -> CommitmentLeafHash {
    CommitmentLeafHash { inner: Poseidon2::hash([commitment.inner, asset_type], 2) }
}

struct CommitmentData {
    blinded_recipient: BlindedRecipient,
    protocol_contract: Field,
    contract_address: Field,
    amount: Field,
    asset_type: Field,
}

/**              zemse's Poseidon2 in solidity only supports 
 *               3 inputs so we cram in ASSET_TYPE like this 😭              GigaRoot
 *                                                         |                   /
 *          everything else + which asset and how much     |   commitmentTreeRoot
 *    note: contractAddr, amount are values in public,     |       /           \
 * during shield/unshield. But not during shielded tx      commitmentLeaf      otherLeafs
 *                                               |          /       |
 *                                               |         /        |
 *              Who owns it + what controls it   |        /         |
 *                                  |           commitment        ASSET_TYPE
 *      to refer to recipient       |          /      |    \             \
 *      without knowing             |         /       |     \            FUNGIBLE or NON_FUNGIBLE 
 *      their chain or pubKey       OwnerHash  contractAddr  amount       
 *              \                  /        \               
 *              BlindedRecipientHash  PROTOCOL_CONTRACT 
 *             / |       |          \
 *        spending  destination    nonce
 *        PubKey     warp         
 *        X and Y    domain                                      
 *                                           
*/
fn hash_commitment_data(data: CommitmentData) -> CommitmentLeafHash {
    let recipient_hash = hash_blinded_recipient(data.blinded_recipient);
    let owner_hash = hash_owner(recipient_hash, data.protocol_contract);
    let commitment = hash_commitment(owner_hash, data.contract_address, data.amount);
    hash_commitment_leaf(commitment, data.asset_type)
}

struct CommitmentDataInclusion<let MAX_DEPTH: u32> {
    commitmentData: CommitmentData,
    proof: LeafInclusionProof<MAX_DEPTH>,
}

fn proof_commitment_to_root<let MAX_DEPTH: u32>(data: CommitmentDataInclusion<MAX_DEPTH>) -> Field {
    let commitment_leaf: CommitmentLeafHash = hash_commitment_data(data.commitmentData);
    leaf_to_root(data.proof, commitment_leaf.inner)
}

fn verify_commitments(
    commitment_proofs: [CommitmentDataInclusion<MAX_TREE_DEPTH>; CIRCUIT_SIZE],
) -> Field {
    let root = proof_commitment_to_root(commitment_proofs[0]);
    for index in 1..CIRCUIT_SIZE {
        assert(
            root == proof_commitment_to_root(commitment_proofs[index]),
            "commitment_proofs are not on the same root: A commitment_proof does not match the root of the first commitment_proof",
        )
    }
    root
}

fn main(
    local_root: pub Field,
    giga_root: pub Field,
    public_hash: pub Field,
    nullifiers: pub [Field; CIRCUIT_SIZE],
    commitment_proofs: [CommitmentDataInclusion<MAX_TREE_DEPTH>; CIRCUIT_SIZE],
    private_sign_data: PrivateSignedData,
    address_secrets: BlindedRecipient,
) {
    let sig_hash: Field = hash_signature_inputs(
        SignedData { private: private_sign_data, public_hash: public_hash },
    );
    // TODO
    let commitment_root: Field = verify_commitments(commitment_proofs);
    if(commitment_root == local_root) {
        // nice we good, no need to check gigaRoot, it was a local transfer!
    } else {
        // check gigaRoot pls!!!
        assert(false, "TODO implementation, inclusion of commitment_root inside the gigaRoot!")
    }
    assert(
        verify(
            address_secrets.spending_key,
            private_sign_data.sig,
            sig_hash,
        ),
    );
}
