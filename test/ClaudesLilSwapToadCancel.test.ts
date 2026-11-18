/**
 * A swaptoad note that its owner takes back, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it into a swaptoad note
 *   2. alice cancels: she spends the note herself with a plain join_split, no order signature, and the 400 come
 *      back to her as a plain note
 *   3. alice unshields that note and unwraps it
 *
 * A swaptoad note has circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that signs
 * orders on it, until when that key may be used, and a nullifier secret of its own. Both a fill and the owner's own
 * spend nullify it with that secret, so once alice has spent it every order she signed on it is dead.
 * Bob is not involved. The fill is ClaudesLilSwapToadFill.test.ts.
 *
 * Needs `pnpm noir` first. Also runs on sepolia, see test/swaptoad.ts:
 *   pnpm hardhat run test/ClaudesLilSwapToadCancel.test.ts --network sepolia
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import type { Note } from "../src/types.js";
import { SWAP_TOAD_SELECTOR } from "../src/constants.js";
import { hashFakeCommitment, hashFakeNullifier, hashNullifier, hashSpendSignatureInputs, type CircuitSizeFields } from "../src/hashing.js";
import {
    fakeNote,
    fakeSpendInput,
    hashNote,
    joinSplitSelectors,
    merkleProofInput,
    noAuth,
    noUnshield,
    prove,
    pubRoots,
    recipientInput,
    spendInput,
} from "../src/proving.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import {
    connectSwapToad,
    MESSAGE_HASHES,
    privateTx,
    PUBLIC_HASH,
    setupToken,
    shieldNote,
    signMessage,
    swapToadStorage,
    unshieldAndUnwrap,
    USDC,
    type TokenSide,
} from "./swaptoad.js";

describe("ClaudesLilSwapToadCancel", async function () {
    const w = await connectSwapToad();
    const { alice, gigaIndex, nonce } = w;
    let usdc: TokenSide;

    // alice owns the offered note with her usual spend key and a nullifier secret used for this one note. A taker
    // would get to see the owner keys hash, and with a fresh secret in it that hash can't be linked to her other notes
    const offerOwner = w.party(alice.eddsaKey, nonce(0x0ffe1), alice.wallet);
    // the note's own nullifier secret, a taker would get it with an order. Nobody gets it here
    const sharedNullifierSecret = nonce(0x5ec1);
    let offered: Note;
    let refund: Note;

    before(async () => {
        usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("400"));
    });

    after(async () => {
        await w.close();
    });

    it("1. alice shields 400 USDC into a swaptoad note", async () => {
        // her order key works on this note for a day
        const authExpiry = (await w.timeStamps()).proof_expire_time_stamp + 86400n;
        offered = {
            ownerHash: offerOwner.ownerHash,
            sharedNonce: nonce(1001),
            assetId: usdc.id,
            amount: USDC("400"),
            circuitCompSelector: SWAP_TOAD_SELECTOR,
            circuitCompStorage: swapToadStorage(alice, { authExpiry, sharedNullifierSecret }),
        };
        await shieldNote(w, usdc, offered, alice.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is shielded");
        assert.deepEqual((await w.tree()).leaves.slice(-1), [hashNote(offered)]);
    });

    it("2. alice cancels without an order signature, the 400 come back as a plain note", async () => {
        const localTree = await w.tree();
        const { proof: offeredProof, edgeIndex } = merkleProofInput(localTree, hashNote(offered));

        // the only real new note: same asset and amount as the offered one, back under alice's main keys
        refund = { ownerHash: alice.ownerHash, sharedNonce: nonce(2001), assetId: usdc.id, amount: offered.amount };
        const recipients = [refund, fakeNote(nonce(2002)), fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(refund),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        // nullified with the note's own secret, not alice's: the same nullifier a fill of this note would have used
        const nullifiers = [
            hashNullifier({ nullifierSecret: sharedNullifierSecret, sharedNonce: offered.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: offeredProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(offered), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(offerOwner.eddsaKey, sigHash);

        const ts = await w.timeStamps();
        const { proof } = await prove(w.backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: PUBLIC_HASH,
                message_hashes: MESSAGE_HASHES,
                unshielding_commitments: [noUnshield(), noUnshield(), noUnshield(), noUnshield()],
                nullifiers,
                recipient_commitments_hashes: recipientHashes,
            },
            priv_in: {
                recipient_commitments: recipients.map(function (n) {
                    return recipientInput(n);
                }),
                actual_amount_recipient_commitments: 1,
                spend_commitments: [
                    spendInput(offered, usdc.asset, offeredProof, edgeIndex),
                    fakeSpendInput(nonce(2005)),
                    fakeSpendInput(nonce(2006)),
                    fakeSpendInput(nonce(2007)),
                ],
                actual_amount_spend_commitments: 1,
                // a cancel is the owner spending their own note through join_split: the keys the note sits under, no order needed
                owner: {
                    pub_key: offerOwner.pubKey,
                    nullifier_secret: offerOwner.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                auth: noAuth(),
                spend_selectors: joinSplitSelectors(),
            },
        });

        const tx = privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof });
        await w.send(w.warptoad.write.transactPrivate([tx]));

        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the offered note is spent");
        assert.deepEqual((await w.tree()).leaves.slice(-4), recipientHashes);
        // and it can't be cancelled twice
        await assert.rejects(w.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });

    it("3. alice unshields the refund and unwraps it", async () => {
        await unshieldAndUnwrap(w, usdc, refund, alice, 3000);
        assert.equal(await usdc.token.read.balanceOf([alice.wallet.account.address]), USDC("400"), "back where she started");
    });
});
