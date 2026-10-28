/**
 * A swaptoad order that gets filled, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it straight into a swaptoad lock, bob wraps 500 DAI and shields it as a
 *      normal note
 *   2. alice signs an order on the lock, 300 USDC for 200 DAI, and bob fills it: 4 new notes, bob builds alice's
 *      two from the lock's shared secret
 *   3. alice unshields the 200 DAI bob made for her and unwraps it, bob does the same with his 300 USDC
 *
 * A lock is a note with circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that
 * signs orders on it plus a shared nullifier secret. The lock is nullified with that secret, not the owner's, so
 * whoever gets the secret with the order can spend the lock, but only the way the order says.
 * The cancel is ClaudesLilSwapToadCancel.test.ts.
 *
 * Needs `pnpm noir` first. Also runs on sepolia, see test/swaptoad.ts:
 *   pnpm hardhat run test/ClaudesLilSwapToadFill.test.ts --network sepolia
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import type { Note } from "../src/types.js";
import { SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashCircuitComponentAuthSig,
    hashFakeNullifier,
    hashNullifier,
    hashSharedNonceSwaptoad,
    hashSpendSignatureInputs,
    type CircuitSizeFields,
} from "../src/hashing.js";
import {
    authSigInputs,
    fakeSpendInput,
    hashNote,
    merkleProofInput,
    noUnshield,
    preCommitmentHashOf,
    prove,
    pubRoots,
    recipientInput,
    spendInput,
} from "../src/proving.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import {
    connectSwapToad,
    DAI,
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

describe("ClaudesLilSwapToadFill", async function () {
    const w = await connectSwapToad();
    const { alice, bob, gigaIndex, nonce } = w;
    let usdc: TokenSide;
    let dai: TokenSide;

    // the lock's shared secret: it nullifies the lock and seeds the nonces of alice's notes on the fill
    const lockSecret = nonce(0x5ec2);
    let lock: Note;
    let bobDai: Note;
    // what the fill leaves them with, unshielded in step 3
    let alicePayment: Note;
    let bobUsdc: Note;

    before(async () => {
        usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("400"));
        dai = await setupToken(w, "DAI", "Dai Stablecoin", 18, bob, DAI("500"));
    });

    after(async () => {
        await w.close();
    });

    it("1. alice locks 400 USDC, bob shields 500 DAI", async () => {
        lock = {
            ownerHash: alice.ownerHash,
            sharedNonce: nonce(1001),
            assetId: usdc.id,
            amount: USDC("400"),
            circuitCompSelector: SWAP_TOAD_SELECTOR,
            circuitCompStorage: lockStorage(alice, lockSecret),
        };
        bobDai = { ownerHash: bob.ownerHash, sharedNonce: nonce(1002), assetId: dai.id, amount: DAI("500") };
        await shieldNote(w, usdc, lock, alice.wallet);
        await shieldNote(w, dai, bobDai, bob.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is in the lock");
        assert.equal(await dai.wrapper.read.balanceOf([bob.wallet.account.address]), 0n);
        assert.deepEqual((await w.tree()).leaves.slice(-2), [hashNote(lock), hashNote(bobDai)]);
    });

    it("2. bob fills alice's order: 300 of the locked USDC for 200 DAI", async () => {
        const localTree = await w.tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(lock));
        const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai));
        const ts = await w.timeStamps();

        // ---- alice's side, all of it before bob shows up: the order, and the two notes bob will make for her.
        // She sells 300 of the 400 locked USDC for 200 DAI, so 1.5 USDC per DAI. Amounts are raw integers in each
        // token's own decimals, the circuit never compares across assets so the different decimals don't matter to it
        const listingAmount = USDC("300");
        const paymentAmount = DAI("200");
        // their nonces come from the lock's secret so bob can't pick them, type 0 is the payment, 1 the change
        alicePayment = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: lockSecret, commitmentType: 0n }),
            assetId: dai.id,
            amount: paymentAmount,
        };
        const aliceChange: Note = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: lockSecret, commitmentType: 1n }),
            assetId: usdc.id,
            amount: lock.amount - listingAmount,
        };
        // `SwapToadOrder` in circuits/src/main.nr, in the order the maker signs it. The order must outlive the proof.
        // first_message_hash pins messages[0] and [1], where the notes for aliceChange and alicePayment would go.
        // The owner keys hash is what lets the circuit check the lock is on this chain's giga index
        const order = authSigInputs([
            usdc.id,
            listingAmount,
            dai.id,
            paymentAmount,
            ts.proof_expire_time_stamp + 3600n,
            FIRST_MESSAGE_HASH,
            preCommitmentHashOf(aliceChange),
            alice.ownerKeysHash,
        ]);
        const orderSig = signMessage(alice.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));

        // ---- bob's side: alice handed him the order, its signature and lockSecret
        const bobChange: Note = { ownerHash: bob.ownerHash, sharedNonce: nonce(2001), assetId: dai.id, amount: bobDai.amount - paymentAmount };
        bobUsdc = { ownerHash: bob.ownerHash, sharedNonce: nonce(2002), assetId: usdc.id, amount: listingAmount };
        // slot order is fixed by the circuit: maker change, maker payment, taker change, taker payment
        const recipients = [aliceChange, alicePayment, bobChange, bobUsdc];
        const recipientHashes = recipients.map(hashNote) as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: lockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashNullifier({ nullifierSecret: bob.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
            hashFakeNullifier({ nonce: nonce(2003) }),
            hashFakeNullifier({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(lock), hashNote(bobDai), 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

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
                actual_amount_recipient_commitments: 4,
                spend_commitments: [
                    spendInput(lock, usdc.asset, lockProof, edgeIndex),
                    spendInput(bobDai, dai.asset, daiProof, edgeIndex),
                    fakeSpendInput(nonce(2003)),
                    fakeSpendInput(nonce(2004)),
                ],
                actual_amount_spend_commitments: 2,
                // bob owns the second spend and signs the tx, alice's order signature authorises the first
                owner: {
                    pub_key: bob.pubKey,
                    nullifier_secret: bob.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                auth: {
                    pub_key: alice.orderPubKey,
                    signature: { x: orderSig.R8[0], y: orderSig.R8[1], scalar: orderSig.S },
                    inputs: order,
                },
                circuit_comp_selector: SWAP_TOAD_SELECTOR,
            },
        });

        const tx = privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof });
        await w.send(w.warptoad.write.transactPrivate([tx]));

        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.equal(await w.warptoad.read.nullifiers([nullifiers[1]]) > 0n, true, "bob's DAI note is spent");
        assert.deepEqual((await w.tree()).leaves.slice(-4), recipientHashes);
        // the lock can't be filled twice
        await assert.rejects(w.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });

    it("3. alice unshields and unwraps the 200 DAI bob made for her, bob his 300 USDC", async () => {
        // the maker's note was built by the taker, so this is the proof it came out spendable
        await unshieldAndUnwrap(w, dai, alicePayment, alice, 3000);
        await unshieldAndUnwrap(w, usdc, bobUsdc, bob, 4000);
        assert.equal(await dai.token.read.balanceOf([alice.wallet.account.address]), DAI("200"));
        assert.equal(await usdc.token.read.balanceOf([bob.wallet.account.address]), USDC("300"));
    });
});
