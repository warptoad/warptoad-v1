use crate::constants::{
    CIRCUIT_COMP_AUTH_SIZE, CIRCUIT_COMP_STORAGE_SIZE, CIRCUIT_SIZE, FAKE_COMMITMENT_DOMAIN,
    FAKE_NULLIFIER_DOMAIN,
};
use crate::{ProvenCommitment, PubKey};
use poseidon::poseidon2::{Poseidon2};

global GIGA_LEAF_DOMAIN: Field = 0x0000000000000000000000000000000000000000000000474947415f4c454146;

/**                                                            # sender needs to share everything in commitment + preCommitmentHash, so: [shared_nonce, CIRCUIT_COMPONENT, asset_id, amount]. maybe also share inputs of asset_id idk. We could store that one time onchain so the encrypted blob wont be huge. owner knows owner_hash inputs, he is literally him
 *   # is it okay that there is there is no domain separator?  /
 *   # everything else + which asset and how much             /                        giga_root             
 *   # note: contractAddr, amount are values in public,      /                        /         \
 *   # during shield/unshield. But not during shielded tx   /                   giga_leaf       other_giga_leaves
 *                                                   |     |                   /    |     \
 *                                                   |     |  ---local_root---   local_   GIGA_LEAF_DOMAIN <- # without this you can confuse with a internal node
 *            # Who owns it + what controls it       |     |/       \             edge_index              \
 *                                |               commitment        otherLeafs..         |                 \
 * to refer to recipient          |              /     |    \                             # needed to verify leaf_index since we need it for the nullifier
 * without knowing                |             /  asset_id  amount
 * their chain or pubKey       pre_commitment_hash          \                                
 *         \                  /   |      \        \          \                            
 *        ----owner_hash-------  shared_  CIRCUIT_ \   wraptoad.sol -> poseidon2(firstGigaIndex,lastGigaIndex, wrapperId )         # for permissioned shielded minting, we should do poseidon here so circuit can do it. + we need to tell wrapperFactoryAddr that it was minted in shielded (so you can block unwrapping), maybe timestamp the mint in asset_id so wrapper factory can refuse unshields of mints passed a time window. Also kind of need a account based note to track total amount minted, 
 *        /               |       nonce   CONTRACT  \                                                      \                       |                                 # for permissionless / ico / payed mints/ we need a different way of thinking. 1. Shielded pay + commit to future time stamp. 2. read randao at that time stamp + mint + commitment has timestamp, then offchain + wrapperFactory derives attribute from that randao as seed.
 * owner_key_hash    giga_index      |              circuit_component_storage_hash        wraptoad.sol -> keccak(wrapperFactoryAddr,_wrapperAssetHash)        
 *     /        \                  to blind         ||        |         |                                                                    |
 * pub_key_     nullifier_secret   commitment     auth_   auth_     shared_                                                          wrapperfactory.sol -> erc20=keccak(wrapperAddr,underlyingAddr), erc721=keccak(wrapperAddr,underlyingAddr, id)
 *   x/y                                           pubkey  expiry    nullifier_       
 *                                                                     secret   \     
 *                                                                               \    
 *                            # note: normal people usually will share            # This example of swaptoad. But can also be: nulltoad, atomictoad, multitoad   
 *                            only thier owner_hash or owner_key_hash             # deferred_inclusion: pre_nullifier, deferred_root.  
 *                            If they want the sender to pick which chain         # WARNING note that anyone shielding can put anything they want into pre_commitment_hash, thus also circuit_component_storage_hash
 *                            They can rotate nullifier_secret to stay            # SO DO NOT TRACK THINGS LIKE AMOUNTS IN THERE
 *                            More anon, but that is not a big issue, since
 *                            onchain. No-one knows they recieved money, only sender knows
 *                            BUT IN SWAP/ATOMIC_TOAD:                                
 *                            Not rotating nullifier_secret will make you recognizable 
 *                            On every trade you will be: "that one retard with that specific- 
 *                            owner_key_hash who didn't rotate nullifier_secret". 
 *                            They dont see `nullifier_secret`, but that is the thing that can make
 *                            owner_key_hash unique after every completed trade
 *                            In general `nullifier_secret` rotate as much as possible.
 *                            For payments and the warptoad address users share around it's fine being the same 
 *                            every time. Might be confusing to constantly change it. People sending fund over might
 *                            get wierded out and constantly want to confirm "is this you?".
 *                            But definitly should be mananaged in sdk to make fresh nullifier_secrets for that address
 *                            And a fresh viewingkey (for encrypted messages) as well. So wallet catered to super users can offer that
 *                            But for trading it's not a super user thing, doxxing on every new trade "i am the same person" is just bad
 *                            The taker in the trade does not need viewkey pubkey, since maker encrypts the blobs for them. 
 *                            So we only need to rotate nullifier_secret. 
 *                            I guess we can just do nullifier_secret = h(nullifier_secret_root, counter)
 *                            And on every encrypted blob synced from a trade. run the counter with numbers not seen before.
 *                            Then for payment rotation do the same but mayber silo out so the counter dont conflict
 *                            nullifier_secret = h(nullifier_secret_root, counter, "<ACCOUNT_TYPE>")
 *                            TODO clean up this brain dump and put into WALLET_SDK_MINDFULLNESS.md
 *
*/  
pub fn hash_giga_leaf(local_root: Field, local_edge_index: Field) -> Field {
    Poseidon2::hash([local_root, local_edge_index, GIGA_LEAF_DOMAIN], 3)
}

pub fn hash_commitment(pre_commitment_hash: Field, asset_id: Field, amount: Field) -> Field {
    Poseidon2::hash([pre_commitment_hash, asset_id, amount], 3)
}

pub fn hash_circuit_component_storage(
    circuit_comp_storage: [Field; CIRCUIT_COMP_STORAGE_SIZE],
) -> Field {
    Poseidon2::hash(circuit_comp_storage, CIRCUIT_COMP_STORAGE_SIZE)
}

pub fn hash_circuit_component_auth_sig(
    inputs: [Field; CIRCUIT_COMP_AUTH_SIZE],
) -> Field {
    Poseidon2::hash(inputs, CIRCUIT_COMP_AUTH_SIZE)
}

pub fn hash_pre_commitment(
    owner_hash: Field,
    shared_nonce: Field,
    circuit_comp_selector: Field,
    circuit_comp_storage_hash: Field,
) -> Field {
    Poseidon2::hash(
        [owner_hash, shared_nonce, circuit_comp_selector, circuit_comp_storage_hash],
        4,
    )
}

// @notice, if a user does not mind telling the recipient what chain they are on
// they can just tell them their owner_keys_hash
// then sender knows and even can set it to any giga_index they choose
// @notice nullifier_secret should not be re-used so you can limit which
// warptoad address reveals on which chain it is on and which does not.
// otherwise owner_keys_hash is the same every time and sender can guess the giga_index
pub fn hash_owner(owner_keys_hash: Field, giga_index: Field) -> Field {
    Poseidon2::hash(
        [owner_keys_hash, giga_index],
        2,
    )
}



pub fn hash_owner_keys(pub_key: PubKey, nullifier_secret: Field) -> Field {
    Poseidon2::hash(
        [pub_key.x, pub_key.y, nullifier_secret],
        3,
    )
}

pub fn hash_spend_signature_inputs(
    public_hash: Field,
    spend_commitments: [ProvenCommitment; CIRCUIT_SIZE],
    recipient_commitments_hashes: [Field; CIRCUIT_SIZE],
) -> Field {
    let mut inputs: [Field; CIRCUIT_SIZE * 2 + 1] = std::mem::zeroed();
    for i in 0..CIRCUIT_SIZE {
        inputs[i] = spend_commitments[i].commitment_hash;
        inputs[CIRCUIT_SIZE + i] = recipient_commitments_hashes[i];
    }
    inputs[CIRCUIT_SIZE * 2] = public_hash;
    Poseidon2::hash(inputs, CIRCUIT_SIZE * 2 + 1)
}

// messages_hash: keccak(encrypted messages) >> 8, mirrored in Warptoad.hashPublic
// other_hash: keccak of whatever else is done in public, 0 for now. Neither is checked here,
// circuit components can constrain messages_hash later (through auth inputs for example)
// @warning constraining it means recomputing keccak over every message *inside* the circuit, and the
// messages are ~3.5KB per tx. Not impossible in noir but expensive. If that day comes, consider hashing the
// messages with poseidon2 in the contract instead (it's 8 gas per byte of calldata either way) or only
// constrain the note tags, which are 32 bytes each
pub fn hash_public(messages_hash: Field, other_hash: Field) -> Field {
    Poseidon2::hash([messages_hash, other_hash], 2)
}

pub fn hash_nullifier(
    nullifier_secret: Field,
    shared_nonce: Field,
    giga_leaf_index: Field,
    local_leaf_index: Field,
) -> Field {
    // using indexes as a protocol gauranteed nonce, 
    // like any combo of giga_index x local_index will never happen twice. The local tree is insert only
    // shared_nonce is added to limit the fall out of a leak + re-use of nullifier_secret
    Poseidon2::hash([nullifier_secret,shared_nonce, giga_leaf_index, local_leaf_index], 4)
}

// this safe since nullifier have 3 inputs but we have 2 here.
// @WARNING set message size to 3 and then bad actors can burn other people funds
// they could create nullifier=h(leaked_shared_nonce, giga_leaf_index_that_happens_to_be_exactly_FAKE_NULLIFIER_DOMAIN, local_leaf_only_at_index_0)
pub fn hash_fake_nullifier(nonce: Field) -> Field {
    Poseidon2::hash([nonce, FAKE_NULLIFIER_DOMAIN], 2)
}

// 2 things that prevent infinite mint bugs here
// FAKE_COMMITMENT_DOMAIN sits at asset_id, which is never a valid asset_id
// commitment_hashes are 3 inputs not 2
pub fn hash_fake_commitment(nonce: Field) -> Field {
    Poseidon2::hash([nonce, FAKE_COMMITMENT_DOMAIN], 2)
}

pub fn hash_asset_id(first_giga_index: Field, last_giga_index: Field, wrapper_id: Field) -> Field {
    Poseidon2::hash([first_giga_index, last_giga_index, wrapper_id], 3)
}

pub fn hash_shared_nonce_swaptoad(shared_nullifier_secret: Field, commitment_type:Field) -> Field {
    Poseidon2::hash([shared_nullifier_secret, commitment_type], 2)
}