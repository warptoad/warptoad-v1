/**
 * A swaptoad order that gets filled, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it straight into a swaptoad note, bob does the same with 500 DAI
 *   2. alice signs an order on her note: the hashes of the two notes she wants out of it, 200 DAI and 100 USDC of
 *      change. bob fills it with his DAI and keeps what is left of her note, 300 USDC. All four new notes are
 *      swaptoad notes again
 *   3. alice unshields the 200 DAI bob made for her and unwraps it, bob does the same with his 300 USDC
 *
 * Every note in here is a swaptoad note, shielded into or made by the fill. So nobody ever needs a tx just to turn a
 * join_split note into one they can sign orders on, and they spend like any other note: bob pays with one in step 2,
 * both unshield from one in step 3.
 *
 * A swaptoad note has circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that signs
 * orders on it, until when that key may be used, and a nullifier secret of its own. With an order a taker can spend
 * it through swaptoad, but only the way the order says. Until then alice can spend it herself with join_split, that is
 * the cancel, see ClaudesLilSwapToadCancel.test.ts. Both ways nullify it with the note's secret, so only one happens.
 * Step 2 spells out what alice hands bob, and bob uses nothing else of hers.
 *
 * Needs `pnpm noir` first. Also runs on sepolia, see test/swaptoad.ts:
 *   pnpm hardhat run test/ClaudesLilSwapToadFill.test.ts --network sepolia
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { JOIN_SPLIT_SELECTOR, SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashCircuitComponentAuthSig,
    hashCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashPublic,
    type CircuitSizeFields,
} from "../src/hashing.js";
import {
    emptyProof,
    fakeSpendInput,
    hashNote,
    merkleProofInput,
    noUnshield,
    prove,
    pubRoots,
    recipientInput,
    sealedRecipientInput,
    sealNote,
    spendInput,
} from "../src/proving.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import {
    connectSwapToad,
    DAI,
    MESSAGE_HASHES,
    privateTx,
    setupToken,
    shieldNote,
    signMessage,
    swapToadNote,
    swapToadOrder,
    swapToadStorageOf,
    unshieldAndUnwrap,
    USDC,
    type SwapToadNote,
    type TokenSide,
} from "./swaptoad.js";

describe("ClaudesLilSwapToadFill", async function () {
    const w = await connectSwapToad();
    const { alice, bob, gigaIndex, nonce } = w;
    let usdc: TokenSide;
    let dai: TokenSide;

    // swaptoad notes, each with an owner, an order key and a nullifier secret of its own, see `swapToadNote`
    let offered: SwapToadNote;
    let bobDai: SwapToadNote;
    // what the fill leaves them with, unshielded in step 3
    let alicePayment: SwapToadNote;
    let bobUsdc: SwapToadNote;

    before(async () => {
        usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("400"));
        dai = await setupToken(w, "DAI", "Dai Stablecoin", 18, bob, DAI("500"));
    });

    after(async () => {
        await w.close();
    });

    it("1. alice shields 400 USDC straight into a swaptoad note, bob 500 DAI", async () => {
        // their order keys work on these notes for a day
        const authExpiry = (await w.timeStamps()).proof_expire_time_stamp + 86400n;
        offered = swapToadNote(w, alice, { assetId: usdc.id, amount: USDC("400"), authExpiry }, 1000);
        bobDai = swapToadNote(w, bob, { assetId: dai.id, amount: DAI("500"), authExpiry }, 1010);
        await shieldNote(w, usdc, offered.note, alice.wallet);
        await shieldNote(w, dai, bobDai.note, bob.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is shielded");
        assert.equal(await dai.wrapper.read.balanceOf([bob.wallet.account.address]), 0n);
        assert.deepEqual((await w.tree()).leaves.slice(-2), [hashNote(offered.note), hashNote(bobDai.note)]);
    });

    it("2. bob fills alice's order: 300 of her 400 USDC for 200 DAI", async () => {
        const ts = await w.timeStamps();
        // every note the fill makes is a swaptoad note again, with order keys that work for a day
        const authExpiry = ts.proof_expire_time_stamp + 86400n;

        // ---- alice's side, all of it before bob shows up: the two notes she wants out of the fill, and the order.
        // She sells 300 of the 400 USDC in her note for 200 DAI, so 1.5 USDC per DAI. Amounts are raw integers in each
        // token's own decimals, the circuit never compares across assets so the different decimals don't matter to it
        const listingAmount = USDC("300");
        const paymentAmount = DAI("200");
        alicePayment = swapToadNote(w, alice, { assetId: dai.id, amount: paymentAmount, authExpiry }, 1020);
        const aliceChange = swapToadNote(w, alice, { assetId: usdc.id, amount: offered.note.amount - listingAmount, authExpiry }, 1030);
        // the order has no amounts or prices in it: alice signs the hashes of her two new notes and of the note that
        // pays for them, whatever is left of that note is the taker's. All or nothing, the order must outlive the proof.
        // Every new note comes with the hash of the message it is announced in, so alice also decides what messages[0]
        // and [1] say. She would encrypt aliceChange and alicePayment to herself there, these tests leave them empty
        const order = swapToadOrder({
            newCommitHashes: [hashNote(aliceChange.note), hashNote(alicePayment.note)],
            spendCommitHashes: [hashNote(offered.note)],
            messageHashes: [MESSAGE_HASHES[0], MESSAGE_HASHES[1]],
            expiry: ts.proof_expire_time_stamp + 3600n,
        });
        const orderSig = signMessage(offered.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));
        // everything alice hands bob. The offered note goes in full, he has to prove it is in the tree: its storage has
        // the key her order is signed with and the secret that nullifies it. With it the owner keys hash its owner hash
        // is made of, the circuit checks the note is owned on this chain. Her two new notes go sealed: the pre
        // commitment hash, asset and amount the circuit reads from a recipient slot. So bob never sees the owner hash
        // or the nonces of what she gets out of the trade, not even that they are swaptoad notes, and none of her secrets
        const fromAlice = {
            offered: offered.note,
            offeredOwnerKeysHash: offered.owner.ownerKeysHash,
            order,
            orderSig,
            change: sealNote(aliceChange.note),
            payment: sealNote(alicePayment.note),
        };

        // ---- bob's side: `fromAlice`, his own DAI note and what is on chain. Nothing else of alice's
        const offeredStorage = swapToadStorageOf(fromAlice.offered);
        const localTree = await w.tree();
        const { proof: offeredProof, edgeIndex } = merkleProofInput(localTree, hashNote(fromAlice.offered));
        const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai.note));
        // he pays what her payment note asks for, and keeps what her change note leaves of the offered one
        const bobChange = swapToadNote(w, bob, { assetId: dai.id, amount: bobDai.note.amount - fromAlice.payment.amount, authExpiry }, 2010);
        bobUsdc = swapToadNote(w, bob, { assetId: usdc.id, amount: fromAlice.offered.amount - fromAlice.change.amount, authExpiry }, 2020);
        // alice's new notes and her offered note sit in the slots her order names them in, the rest is bob's
        const recipientHashes = [
            hashCommitment(fromAlice.change),
            hashCommitment(fromAlice.payment),
            hashNote(bobChange.note),
            hashNote(bobUsdc.note),
        ] as CircuitSizeFields;
        // both spent notes are swaptoad notes, so both are nullified with their own secret. Alice's through swaptoad,
        // bob's own through join_split
        const nullifiers = [
            hashNullifier({ nullifierSecret: offeredStorage.sharedNullifierSecret, sharedNonce: fromAlice.offered.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: offeredProof.index }),
            hashNullifier({ nullifierSecret: swapToadStorageOf(bobDai.note).sharedNullifierSecret, sharedNonce: bobDai.note.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
            hashFakeNullifier({ nonce: nonce(2003) }),
            hashFakeNullifier({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        // what the spender authorizes: every message, unshield, nullifier and new note of this tx. The contract
        // computes the same hash, see `hashPublic`
        const unshielding = [noUnshield(), noUnshield(), noUnshield(), noUnshield()];
        const publicHash = hashPublic({ messageHashes: MESSAGE_HASHES, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
        const sig = signMessage(bobDai.owner.eddsaKey, publicHash);

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
                recipient_commitments: [
                    sealedRecipientInput(fromAlice.change),
                    sealedRecipientInput(fromAlice.payment),
                    recipientInput(bobChange.note),
                    recipientInput(bobUsdc.note),
                ],
                actual_amount_recipient_commitments: 4,
                spend_commitments: [
                    spendInput(fromAlice.offered, usdc.asset, offeredProof, edgeIndex, emptyProof(), fromAlice.offeredOwnerKeysHash),
                    spendInput(bobDai.note, dai.asset, daiProof, edgeIndex),
                    fakeSpendInput(nonce(2003)),
                    fakeSpendInput(nonce(2004)),
                ],
                actual_amount_spend_commitments: 2,
                // bob owns the second spend and signs the tx with the keys that note sits under, alice's order signature
                // authorises the first
                owner: {
                    pub_key: bobDai.owner.pubKey,
                    nullifier_secret: bobDai.owner.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                auth: {
                    pub_key: offeredStorage.orderPubKey,
                    signature: { x: fromAlice.orderSig.R8[0], y: fromAlice.orderSig.R8[1], scalar: fromAlice.orderSig.S },
                    inputs: fromAlice.order,
                },
                // swaptoad checks alice's note against her order, join_split checks bob's own note. Fakes are join_split's
                spend_selectors: [SWAP_TOAD_SELECTOR, JOIN_SPLIT_SELECTOR, JOIN_SPLIT_SELECTOR, JOIN_SPLIT_SELECTOR],
            },
        });

        const tx = privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof });
        await w.send(w.warptoad.write.transactPrivate([tx]));

        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "alice's offered note is spent");
        assert.equal(await w.warptoad.read.nullifiers([nullifiers[1]]) > 0n, true, "bob's DAI note is spent");
        assert.deepEqual((await w.tree()).leaves.slice(-4), recipientHashes);
        // the order can't be filled twice
        await assert.rejects(w.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });

    it("3. alice unshields and unwraps the 200 DAI bob made for her, bob his 300 USDC", async () => {
        // the maker's note was built by the taker, so this is the proof it came out spendable. Both are swaptoad notes,
        // spent with a plain join_split by the keys they sit under
        await unshieldAndUnwrap(w, dai, alicePayment.note, alicePayment.owner, 3000);
        await unshieldAndUnwrap(w, usdc, bobUsdc.note, bobUsdc.owner, 4000);
        assert.equal(await dai.token.read.balanceOf([alice.wallet.account.address]), DAI("200"));
        assert.equal(await usdc.token.read.balanceOf([bob.wallet.account.address]), USDC("300"));
    });
});
