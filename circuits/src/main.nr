use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;

pub struct PubKey {
    x: Field,
    y: Field,
}

pub struct Signature {
    x: Field,
    y: Field,
    scalar: Field,
}

pub fn verify(pub_key: PubKey, sig: Signature, message: Field) -> bool {
    // eddsa_verify (aka baby jub jub) signing + poseidon already exists in circom
    // so we do that instead of poseidon2 to make switching easier.
    eddsa_verify::<PoseidonHasher>(pub_key.x, pub_key.y, sig.scalar, sig.x, sig.y, message)
}

fn main(key: pub PubKey, sig: Signature, message: pub Field) {
    assert(verify(key, sig, message));
}

mod tests {
    use super::{PubKey, Signature, verify};

    // Baby jubjub keys/signatures over message 789, taken from the upstream
    // noir-lang/eddsa test vectors. Guards the patched `lib/ec` + `lib/eddsa`
    // (see ../lib/README.md) against a regression in the curve arithmetic.
    global MESSAGE: Field = 789;

    global KEY_A: PubKey = PubKey {
        x: 0x16b051f37589e0dcf4ad3c415c090798c10d3095bedeedabfcc709ad787f3507,
        y: 0x062800ac9e60839fab9218e5ed9d541f4586e41275f4071816a975895d349a5e,
    };

    // A's signature over MESSAGE
    global SIG_A: Signature = Signature {
        x: 0x163814666f04c4d2969059a6b63ee26a0f9f0f81bd5957b0796e2e8f4a8a2f06,
        y: 0x1255b17d9e4bfb81831625b788f8a1665128079ac4b6c8c3cd1b857666a05a54,
        scalar: 30333430637424319196043722294837632681219980330991241982145549329256671548,
    };

    // B's signature over MESSAGE, i.e. one that A's public key must reject
    global SIG_B: Signature = Signature {
        x: 0x0277c2a563bd070e02542943b70a70e20cf08e165269bdb757afcee5d7fcbea7,
        y: 0x29ab39e116d2b45865e6220d8dfdf7f7615f1a5097f96d7db0d5b6340c0d3002,
        scalar: 1646085314320208098241070054368798527940102577261034947654839408482102287019,
    };

    #[test]
    fn verifies_valid_signature() {
        assert(verify(KEY_A, SIG_A, MESSAGE));
    }

    #[test]
    fn rejects_other_signers_signature() {
        assert(!verify(KEY_A, SIG_B, MESSAGE));
    }

    #[test]
    fn rejects_signature_over_another_message() {
        assert(!verify(KEY_A, SIG_A, MESSAGE + 1));
    }

    #[test]
    fn main_accepts_valid_signature() {
        super::main(KEY_A, SIG_A, MESSAGE);
    }
}
