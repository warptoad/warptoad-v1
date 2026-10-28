/**
 * A swaptoad lock that gets cancelled, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it straight into a swaptoad lock
 *   2. alice cancels the lock: no order signature, the 400 come back to her as a plain note
 *   3. alice unshields that note and unwraps it
 *
 * A lock is a note with circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that
 * signs orders on it plus a shared nullifier secret. The lock is nullified with that secret, not the owner's, so a
 * cancel and a fill spend the same nullifier. Bob is not involved. The fill is ClaudesLilSwapToadFill.test.ts.
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
import { fakeNote, fakeSpendInput, hashNote, merkleProofInput, noAuth, noUnshield, prove, pubRoots, recipientInput, spendInput } from "../src/proving.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import {
    connectSwapToad,
    FIRST_MESSAGE_HASH,
    lockStorage,
    privateTx,
    PUBLIC_HASH,
    setupToken,
    shieldNote,
    signMessage,
    unshieldAndUnwrap,
    USDC,
    type TokenSide,
} from "./swaptoad.js";

describe("ClaudesLilSwapToadCancel", async function () {
    const w = await connectSwapToad();
    const { alice, gigaIndex, nonce } = w;
    let usdc: TokenSide;

    // the lock's shared secret: it nullifies the lock, whoever alice gives it to can fill. Nobody gets it here
    const lockSecret = nonce(0x5ec1);
    let lock: Note;
    let refund: Note;

    before(async () => {
        usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("400"));
    });

    after(async () => {
        await w.close();
    });

    it("1. alice locks 400 USDC", async () => {
        lock = {
            ownerHash: alice.ownerHash,
            sharedNonce: nonce(1001),
            assetId: usdc.id,
            amount: USDC("400"),
            circuitCompSelector: SWAP_TOAD_SELECTOR,
            circuitCompStorage: lockStorage(alice, lockSecret),
        };
        await shieldNote(w, usdc, lock, alice.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is in the lock");
        assert.deepEqual((await w.tree()).leaves.slice(-1), [hashNote(lock)]);
    });

    it("2. alice cancels without an order signature, the 400 come back as a plain note", async () => {
        const localTree = await w.tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(lock));

        // the only real new note: same asset and amount as the lock, the circuit checks nothing else about it
        refund = { ownerHash: alice.ownerHash, sharedNonce: nonce(2001), assetId: usdc.id, amount: lock.amount };
        const recipients = [refund, fakeNote(nonce(2002)), fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(refund),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        // the lock is nullified with its shared secret, not alice's own
        const nullifiers = [
            hashNullifier({ nullifierSecret: lockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(lock), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(alice.eddsaKey, sigHash);

        const ts = await w.timeStamps();
        const { proof } = await prove(w.backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: PUBLIC_HASH,
                first_message_hash: FIRST_MESSAGE_HASH,
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
                    spendInput(lock, usdc.asset, lockProof, edgeIndex),
                    fakeSpendInput(nonce(2005)),
                    fakeSpendInput(nonce(2006)),
                    fakeSpendInput(nonce(2007)),
                ],
                actual_amount_spend_commitments: 1,
                owner: {
                    pub_key: alice.pubKey,
                    nullifier_secret: alice.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                // no auth signature is how the circuit tells a cancel from a fill, the owner signature is enough
                auth: noAuth(),
                circuit_comp_selector: SWAP_TOAD_SELECTOR,
            },
        });

        const tx = privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof });
        await w.send(w.warptoad.write.transactPrivate([tx]));

        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.deepEqual((await w.tree()).leaves.slice(-4), recipientHashes);
        // and it can't be cancelled twice
        await assert.rejects(w.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });

    it("3. alice unshields the refund and unwraps it", async () => {
        await unshieldAndUnwrap(w, usdc, refund, alice, 3000);
        assert.equal(await usdc.token.read.balanceOf([alice.wallet.account.address]), USDC("400"), "back where she started");
    });
});
