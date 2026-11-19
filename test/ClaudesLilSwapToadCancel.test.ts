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
import { hashFakeCommitment, hashFakeNullifier, hashNullifier, hashPublic, type CircuitSizeFields } from "../src/hashing.js";
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
    setupToken,
    shieldNote,
    signMessage,
    swapToadNote,
    swapToadStorageOf,
    unshieldAndUnwrap,
    USDC,
    type SwapToadNote,
    type TokenSide,
} from "./swaptoad.js";

describe("ClaudesLilSwapToadCancel", async function () {
    const w = await connectSwapToad();
    const { alice, gigaIndex, nonce } = w;
    let usdc: TokenSide;

    // a swaptoad note with an owner, an order key and a nullifier secret of its own, see `swapToadNote`. A taker would
    // get to see some of that with an order, nobody does here
    let offered: SwapToadNote;
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
        offered = swapToadNote(w, alice, { assetId: usdc.id, amount: USDC("400"), authExpiry }, 1000);
        await shieldNote(w, usdc, offered.note, alice.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is shielded");
        assert.deepEqual((await w.tree()).leaves.slice(-1), [hashNote(offered.note)]);
    });

    it("2. alice cancels without an order signature, the 400 come back as a plain note", async () => {
        const localTree = await w.tree();
        const { proof: offeredProof, edgeIndex } = merkleProofInput(localTree, hashNote(offered.note));

        // the only real new note: same asset and amount as the offered one, back under alice's main keys
        refund = { ownerHash: alice.ownerHash, sharedNonce: nonce(2001), assetId: usdc.id, amount: offered.note.amount };
        const recipients = [refund, fakeNote(nonce(2002)), fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(refund),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        // nullified with the note's own secret, not alice's: the same nullifier a fill of this note would have used
        const nullifiers = [
            hashNullifier({ nullifierSecret: swapToadStorageOf(offered.note).sharedNullifierSecret, sharedNonce: offered.note.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: offeredProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
        ] as CircuitSizeFields;
        // what the spender authorizes: every message, unshield, nullifier and new note of this tx. The contract
        // computes the same hash, see `hashPublic`
        const unshielding = [noUnshield(), noUnshield(), noUnshield(), noUnshield()];
        const publicHash = hashPublic({ messageHashes: MESSAGE_HASHES, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
        const sig = signMessage(offered.owner.eddsaKey, publicHash);

        const ts = await w.timeStamps();
        const { proof } = await prove(w.backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: publicHash,
                message_hashes: MESSAGE_HASHES,
                unshielding_commitments: unshielding,
                nullifiers,
                recipient_commitments_hashes: recipientHashes,
            },
            priv_in: {
                recipient_commitments: recipients.map(function (n) {
                    return recipientInput(n);
                }),
                actual_amount_recipient_commitments: 1,
                spend_commitments: [
                    spendInput(offered.note, usdc.asset, offeredProof, edgeIndex),
                    fakeSpendInput(nonce(2005)),
                    fakeSpendInput(nonce(2006)),
                    fakeSpendInput(nonce(2007)),
                ],
                actual_amount_spend_commitments: 1,
                // a cancel is the owner spending their own note through join_split: the keys the note sits under, no order needed
                owner: {
                    pub_key: offered.owner.pubKey,
                    nullifier_secret: offered.owner.nullifierSecret,
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
