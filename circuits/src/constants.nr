use poseidon::poseidon2::Poseidon2;

pub global CIRCUIT_SIZE: u32 = 4;
// ORDER SIZE is limited by the max amount of nullifiers emitted
// 3x nullifiers to spend 3 maker commitments. Then 1x nullifier to spend takers payement commitment
// But do remember that a maker making a order with 3 different asset_ids, all partially spend commitments
// will cause 3 change commitments being made for maker. That is 3x3 new commitments, not possible to fill!
// TLDR: bigger then 1 order_size = nft only / all fully spend commitments

// --- TODO for the "fee abstraction" use case. make circuit size for spends 4 but new_commits 6: ---
// ex: DAI -> USDC. But no eth for gas
//-------------------------------------------
// maker spend: 150 USDC
// maker spend: 1 ETH
// taker spend: 100 DAI
// ----total commits spend/nullified: 3 ----
// taker takes:     0.0005 ETH (unshielded,spend for gas)
// taker takes:     0.00002345 ETH reshielded after gas spend had something left over
// taker takes:     99 USDC (the trade they wanted)
// maker takes:     100 DAI (trade they provided)
// maker change:    0.9995 ETH
// maker change:    51 USDC
// ---- total new commits created: 6 -------
// Nullifiers are also more limited when doing frame txs. Since they are a constraint on spendability.
// And therefor are part of the verification frame. Which has tight af limits

// but not other way around.
pub global SWAP_TOAD_ORDER_SIZE: u32 = CIRCUIT_SIZE - 1;
pub global SWAP_TOAD_MISC_AUTH_INPUTS: u32 = 1;
// 3*order_size because maker want to sign either 3 commitment_hash to constrain payment (so ex recieve 3 different asset_ids)
// Or sell 3 different asset_ids
// then it also needs to contrain the public messages hashes in the case of recieving 3 payment commitments
pub global NON_CIRCTUIT_COMP_AUTH_INPUTS: u32 = 1;
pub global CIRCUIT_COMP_AUTH_SIZE: u32 =
    NON_CIRCTUIT_COMP_AUTH_INPUTS + 3 * SWAP_TOAD_ORDER_SIZE + SWAP_TOAD_MISC_AUTH_INPUTS;
pub global CIRCUIT_COMP_STORAGE_SIZE: u32 = 3;
pub global CIRCUIT_COMP_STORAGE_EMPTY: [Field; CIRCUIT_COMP_STORAGE_SIZE] = std::mem::zeroed();
pub global CIRCUIT_COMP_STORAGE_EMPTY_HASH: Field =
    Poseidon2::hash(CIRCUIT_COMP_STORAGE_EMPTY, CIRCUIT_COMP_STORAGE_SIZE);
// to match aztec note_hash_tree, also we need to put edge index at 2**40 - 1 there
// no tree resets: at ~12M leaves/day 2^40 lasts ~250 years, quantum breaks bn254 first
pub global MAX_TREE_DEPTH: u32 = 40;
//   let unPadded = [...new TextEncoder().encode("JOIN_SPLIT")].map(b=>b.toString(16));
//     "0x" + [...new Array(32-unPadded.length).fill("00"), ...unPadded].join("");
pub global JOIN_SPLIT_SELECTOR: Field =
    0x000000000000000000000000000000000000000000004a4f494e5f53504c4954;

pub global SWAP_TOAD_SELECTOR: Field =
    0x0000000000000000000000000000000000000000000000544f41445f53574150;

pub global JOIN_SPLIT_NULLIFIER_SLOT: Field = 0x00;
pub global SWAP_NULLIFIER_SLOT: Field = 0x00;
pub global SWAP_TIMER_NULLIFIER_SLOT: Field = 0x01;

// let unPadded = [...new TextEncoder().encode("FAKE_NULLIFIER")].map(b=>b.toString(16));
//     "0x" + [...new Array(32-unPadded.length).fill("00"), ...unPadded].join("");
pub global FAKE_NULLIFIER_DOMAIN: Field =
    0x00000000000000000000000000000000000046414b455f4e554c4c4946494552;
pub global FAKE_COMMITMENT_DOMAIN: Field =
    0x000000000000000000000000000000000046414b455f434f4d4d49544d454e54;
