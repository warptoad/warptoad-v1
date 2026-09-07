use crate::constants::{CIRCUIT_CONTR_STORAGE_SIZE, CIRCUIT_SIZE};
use crate::{ProvenCommitment, PubKey};
use poseidon::{poseidon2::{self, Poseidon2}, poseidon::PoseidonHasher};
global GIGA_LEAF_DOMAIN: Field = 0x0000000000000000000000000000000000000000000000474947415f4c454146;

/**                                                            # sender needs to share everything in commitment + preCommitmentHash, so: [shared_nonce, CIRCUIT_CONTRACT, asset_id, amount]. maybe also share inputs of asset_id idk. We could store that one time onchain so the encrypted blob wont be huge. owner knows owner_hash inputs, he is literally him
 *   # is it okay that there is there is no domain separator?  /
 *   # everything else + which asset and how much             /                        giga_root             
 *   # note: contractAddr, amount are values in public,      /                        /         \
 *   # during shield/unshield. But not during shielded tx   /                   giga_leaf       other_giga_leaves
 *                                                   |     |                   /    |     \
 *                                                   |     |  ---local_root---   local_   GIGA_LEAF_DOMAIN <- # without this you can confuse with a internal node
 *            # Who owns it + what controls it       |     |/       \             edge_index               \
 *                                |               commitment        otherLeafs..      |                     \
 * to refer to recipient          |              /     |    \                         |             # needed to verify leaf_index since we need it for the nullifier
 * without knowing                |             /      |     \
 * their chain or pubKey       pre_commitment_hash    asset_id  amount <- erc20=amount,721=1, 1155=amount of that nft id     
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

pub fn hash_giga_leaf(local_root: Field, local_edge_index: Field) -> Field {
    Poseidon2::hash([local_root, local_edge_index, GIGA_LEAF_DOMAIN], 3)
}

pub fn hash_commitment(pre_commitment_hash: Field, asset_id: Field, amount: Field) -> Field {
    Poseidon2::hash([pre_commitment_hash, asset_id, amount], 3)
}

pub fn hash_circuit_contract_storage(
    circuit_contr_storage: [Field; CIRCUIT_CONTR_STORAGE_SIZE],
) -> Field {
    Poseidon2::hash(circuit_contr_storage, CIRCUIT_CONTR_STORAGE_SIZE)
}

pub fn hash_pre_commitment(
    owner_hash: Field,
    shared_nonce: Field,
    circuit_contr_selector: Field,
    circuit_contr_storage_hash: Field,
) -> Field {
    Poseidon2::hash(
        [owner_hash, shared_nonce, circuit_contr_selector, circuit_contr_storage_hash],
        4,
    )
}

pub fn hash_owner(spend_pub_key: PubKey, dest_giga_index: Field, nullifier_secret: Field) -> Field {
    Poseidon2::hash(
        [spend_pub_key.x, spend_pub_key.y, dest_giga_index, nullifier_secret],
        4,
    )
}

pub fn hash_signature_inputs(
    public_hash: Field,
    spend_commitments: [ProvenCommitment; CIRCUIT_SIZE],
    recipient_commitments_hashes: [Field; CIRCUIT_SIZE],
) -> Field {
    let mut inputs: [Field; CIRCUIT_SIZE * 2] = std::mem::zeroed();
    let offset: u32 = 1;
    inputs[0] = public_hash;
    for i in offset..CIRCUIT_SIZE {
        inputs[i] = spend_commitments[i].commitment_hash;
        inputs[CIRCUIT_SIZE + i] = recipient_commitments_hashes[i];
    }
    Poseidon2::hash(inputs, CIRCUIT_SIZE * 2 + offset)
}
