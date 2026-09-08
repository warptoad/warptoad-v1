use poseidon::poseidon2::Poseidon2;

// asset_id, amount, expiry, ref_to_lock.
// so set to 7 since poseidon2 cost scale per oder 4 with the first being 3 for size domain separation
// tldr we need 4 inputs, might as well support 7 since no added cost
pub global CIRCUIT_CONTR_AUTH_SIZE: u32 = 7;
pub global CIRCUIT_CONTR_STORAGE_SIZE: u32 = 3;
pub global CIRCUIT_CONTR_STORAGE_EMPTY: [Field; CIRCUIT_CONTR_STORAGE_SIZE] = std::mem::zeroed();
pub global CIRCUIT_CONTR_STORAGE_EMPTY_HASH: Field =
    Poseidon2::hash(CIRCUIT_CONTR_STORAGE_EMPTY, CIRCUIT_CONTR_STORAGE_SIZE);
pub global CIRCUIT_SIZE: u32 = 4;
// to match aztec note_hash_tree, also we need to put edge index at 2**40 - 1 there
// no tree resets: at ~12M leaves/day 2^40 lasts ~250 years, quantum breaks bn254 first
pub global MAX_TREE_DEPTH: u32 = 40;
//   let unPadded = [...new TextEncoder().encode("JOIN_SPLIT")].map(b=>b.toString(16));
//     "0x" + [...new Array(32-unPadded.length).fill("00"), ...unPadded].join("");
pub global JOIN_SPLIT_SELECTOR: Field =
    0x000000000000000000000000000000000000000000004a4f494e5f53504c4954;

pub global JOIN_SPLIT_NULLIFIER_SLOT: Field = 0x00;
pub global SWAP_NULLIFIER_SLOT: Field = 0x00;
pub global SWAP_TIMER_NULLIFIER_SLOT: Field = 0x01;

// let unPadded = [...new TextEncoder().encode("FAKE_NULLIFIER")].map(b=>b.toString(16));
//     "0x" + [...new Array(32-unPadded.length).fill("00"), ...unPadded].join("");
pub global FAKE_NULLIFIER_DOMAIN: Field = 0x00000000000000000000000000000000000046414b455f4e554c4c4946494552;
pub global FAKE_COMMITMENT_DOMAIN: Field = 0x000000000000000000000000000000000046414b455f434f4d4d49544d454e54;
