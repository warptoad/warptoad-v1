use poseidon::poseidon2::Poseidon2;

pub struct LeafInclusionProof<let MAX_DEPTH: u32> {
    // unconstrained_index since we use leanIMT structure, we can't trust the index since the tree is not balanced
    // some leafs might sit at a higher level meaning their proofIndex (unconstrained_index) is lower then expected
    pub unconstrained_index: Field,
    pub depth: u32,
    // MAX_DEPTH is usually deeper then the actual proof, just pad the end of the array with zeros
    pub siblings: [Field; MAX_DEPTH],
}

pub struct LeafAndIndexInclusionProof<let MAX_TREE_DEPTH: u32> {
    pub index: Field,
    pub leaf: Field,
    pub depth: u32,
    pub siblings: [Field; MAX_TREE_DEPTH],
}

pub fn leaf_to_root<let MAX_DEPTH: u32>(proof:LeafInclusionProof<MAX_DEPTH>, leaf:Field) -> Field {
    let index_bits: [bool; MAX_DEPTH] = proof.unconstrained_index.to_le_bits();
    let mut node: Field = leaf;
    for i in 0..proof.depth {
        let sibling: Field = proof.siblings[i];
        let mut left: Field = node;
        let mut right: Field = sibling;
        if index_bits[i] {
            left = sibling;
            right = node;
        }
        node = Poseidon2::hash([left, right], 2);
    }
    node
}

// this verifies the actual index and leaf, instead of only the leaf like in leaf_to_root
pub fn leaf_and_index_to_root<let MAX_DEPTH: u32>(proof: LeafAndIndexInclusionProof<MAX_DEPTH>, leaf: Field) -> Field {
    assert(false, "TODO implementation leaf_and_index_to_root()");
    // see https://github.com/warptoad/skinny-fat-imt/blob/00ccdc11539131ebd69a491ac59092ad8e8ed106/packages/skinny-imt/contracts/InternalSkinnyIMTCore.sol#L645-L689
    // on how to implement 
    0
}