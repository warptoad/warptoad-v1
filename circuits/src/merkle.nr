use poseidon::poseidon2::Poseidon2;

pub struct LeafInclusionProof<let MAX_DEPTH: u32> {
    // unconstrained_index since we use leanIMT structure, we can't trust the index since the tree is not balanced
    // some leafs might sit at a higher level meaning their proofIndex (unconstrained_index) is lower then expected
    pub unconstrained_index: Field,
    pub depth: u32,
    // MAX_DEPTH is usually deeper then the actual proof, just pad the end of the array with zeros
    pub siblings: [Field; MAX_DEPTH],
}

pub struct LeafAndIndexInclusionProof<let MAX_DEPTH: u32> {
    // here we can trust the index :D (as long as edge_index comes from a trusted source!)
    pub index: Field,
    // leanIMT js gives a compressed siblings array (hoisted levels are omitted).
    // js must re-align it to one-sibling-per-level by inserting a 0 at each hoisted level
    // (hoisted when: nodeIndex == edgeIndex && nodeIndex is even, halving both per level).
    // the 0s are just spacers so we can index by level, the circuit ignores them.
    // also pad the end of the array with zeros up to MAX_DEPTH
    pub siblings: [Field; MAX_DEPTH],
}

// unused. Is cute optimization, leanIMT has leafs sitting higher up closer to root when the tree is unbalanced.
// allows for lower depth proofs, but those leaf eventually go down, forcing our circuit to go deep anyway at that point
// so better of just using leaf_and_index_to_root, so we also constraint the index properly so we can use it in the nullifiers
// Maybe we can use this mechanism? It is basically a "get a fresh tree once it's too big" like railgun does.
// but with the added benefit that everything is in one tree.
// we could have a not so expensive function that calculates the shortened "not really index" then
// verify with this thing on a lower depth, which would be better then leaf_and_index_to_root
// TODO re-read ur ramblings and do that i guess.
// pub fn leaf_to_root<let MAX_DEPTH: u32>(
//     proof: LeafInclusionProof<MAX_DEPTH>,
//     leaf: Field,
// ) -> Field {
//     let index_bits: [bool; MAX_DEPTH] = proof.unconstrained_index.to_le_bits();
//     let mut node: Field = leaf;
//     for i in 0..proof.depth {
//         let sibling: Field = proof.siblings[i];
//         let mut left: Field = node;
//         let mut right: Field = sibling;
//         if index_bits[i] {
//             left = sibling;
//             right = node;
//         }
//         node = Poseidon2::hash([left, right], 2);
//     }
//     node
// }

// this verifies the actual index and leaf, instead of only the leaf like in leaf_to_root
// @warning edge_index (index of the last leaf, treeSize - 1) MUST come from a trusted source (contract, together with the root)!
// if the prover picks edge_index they can fake extra hoist-skips and prove the same leaf under a different index
// -> different nullifier -> double spend
// there is some overhead compared to leaf_to_root, according to claude it's the equivalent of 4,4 poseidon2 hashes in total at depth 32
pub fn leaf_and_index_to_root<let MAX_DEPTH: u32>(
    proof: LeafAndIndexInclusionProof<MAX_DEPTH>,
    leaf: Field,
    edge_index: Field
) -> Field {
    // also range-constrains both to MAX_DEPTH bits
    let index_bits: [bool; MAX_DEPTH] = proof.index.to_le_bits();
    let edge_bits: [bool; MAX_DEPTH] = edge_index.to_le_bits();

    // walk top down: on_edge[i] == ((index >> i) == (edge_index >> i))
    let mut on_edge: [bool; MAX_DEPTH] = [false; MAX_DEPTH];
    let mut eq: bool = true;
    for j in 0..MAX_DEPTH {
        // noir cant count backwards, bro would fail the drug test
        let i = MAX_DEPTH - 1 - j;
        eq = eq & (index_bits[i] == edge_bits[i]);
        on_edge[i] = eq;
    }

    let mut node: Field = leaf;
    for i in 0..MAX_DEPTH {
        // last node at this level as a left child has no right sibling: value hoists up unchanged.
        // above the real tree depth index == edge_index == 0 so everything skips, no depth field needed
        let skip: bool = on_edge[i] & !index_bits[i];
        // static index thanks to the js-side padding. a runtime cursor here costs ~41 poseidon2s in RAM gates
        let sibling: Field = proof.siblings[i];
        let (left, right) = if index_bits[i] {
            (sibling, node)
        } else {
            (node, sibling)
        };
        let hashed: Field = Poseidon2::hash([left, right], 2);
        node = if skip { node } else { hashed };
    }
    node
}
// converts a real leaf index to a "proof index" but returns as a deconstructed array of bools already since that is more efficient
// commented out, because untested and unoptimized. Will just use leaf_and_index_to_root since we're better of just resetting the whole tree
// when it out grows. Then we can re-use those storage slots
// but this would allow is to support a infinitely growing tree, but some old deposits might need to use outdated roots in order to have their leaf to be in 
// the dangling right side of the tree where the leafs are higher up close to root. But at that point you have the same properties as just resetting the tree without 
// re-using slot lol
// only difference is that you have a nice root with everything in it always. It gives us the option to provide a giant circuit so you can always use a recent root even 
// if ur a very old leaf in a very big tree, nice but niche
// pub fn index_to_hash_order<let MAX_DEPTH: u32>(
//     mut index: u128,
//     mut edge_index: u128,
// ) -> [bool; MAX_DEPTH] {
//     assert(index <= edge_index, "leaf index cant be beyond the edge index");
//     let mut hash_orders: [bool; MAX_DEPTH] = std::mem::zeroed();
//     let mut hash_orders_arr_index: u32 = 0;
//     for _ in 0..MAX_DEPTH {
//         // we might be able to keep them as fields if we do:
//         // let bits: [u1 field; 32] = num.to_le_bits()
//         // bits[0] == 0, that also might be more efficient? idk
//         if (index & 1 == 1) {
//             hash_orders[hash_orders_arr_index] = true;
//             hash_orders_arr_index += 1;
//         } else {
//             if (index != edge_index) {
//                 hash_orders[hash_orders_arr_index] = false;
//                 hash_orders_arr_index += 1;
//             }
//             // @notice, if index == edge_index, that means the node was hoisted up
//             // so we skip that entry
//         }
//         index /= 2;
//         edge_index /= 2
//     }
//     hash_orders
// }
