/**
 * A swaptoad order that gets filled, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it into a swaptoad note, bob wraps 500 DAI and shields it as a normal note
 *   2. alice signs an order on her note: the hashes of the two notes she wants out of it, 200 DAI and 100 USDC of
 *      change. bob fills it with his DAI and keeps what is left of her note, 300 USDC
 *   3. alice unshields the 200 DAI bob made for her and unwraps it, bob does the same with his 300 USDC
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
import type { Note } from "../src/types.js";
import { JOIN_SPLIT_SELECTOR, SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashCircuitComponentAuthSig,
    hashCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashSpendSignatureInputs,
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
    PUBLIC_HASH,
    setupToken,
    shieldNote,
    signMessage,
    swapToadOrder,
    swapToadStorage,
    swapToadStorageOf,
    unshieldAndUnwrap,
    USDC,
    type TokenSide,
} from "./swaptoad.js";

describe("ClaudesLilSwapToadFill", async function () {
    const w = await connectSwapToad();
    const { alice, bob, gigaIndex, nonce } = w;
    let usdc: TokenSide;
    let dai: TokenSide;

    // alice owns the offered note with her usual spend key and a nullifier secret used for this one note. The taker
    // gets to see the owner keys hash, and with a fresh secret in it that hash can't be linked to her other notes.
    // The owner hash her payment and change go to never leaves her
    const offerOwner = w.party(alice.eddsaKey, nonce(0x0ffe2), alice.wallet);
    // the note's own nullifier secret. It sits in the note's storage, so bob gets it with the note
    const sharedNullifierSecret = nonce(0x5ec2);
    let offered: Note;
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

    it("1. alice shields 400 USDC into a swaptoad note, bob shields 500 DAI", async () => {
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
        bobDai = { ownerHash: bob.ownerHash, sharedNonce: nonce(1002), assetId: dai.id, amount: DAI("500") };
        await shieldNote(w, usdc, offered, alice.wallet);
        await shieldNote(w, dai, bobDai, bob.wallet);

        assert.equal(await usdc.wrapper.read.balanceOf([alice.wallet.account.address]), 0n, "all of it is shielded");
        assert.equal(await dai.wrapper.read.balanceOf([bob.wallet.account.address]), 0n);
        assert.deepEqual((await w.tree()).leaves.slice(-2), [hashNote(offered), hashNote(bobDai)]);
    });

    it("2. bob fills alice's order: 300 of her 400 USDC for 200 DAI", async () => {
        const ts = await w.timeStamps();

        // ---- alice's side, all of it before bob shows up: the two notes she wants out of the fill, and the order.
        // She sells 300 of the 400 USDC in her note for 200 DAI, so 1.5 USDC per DAI. Amounts are raw integers in each
        // token's own decimals, the circuit never compares across assets so the different decimals don't matter to it
        const listingAmount = USDC("300");
        const paymentAmount = DAI("200");
        alicePayment = { 
            ownerHash: alice.ownerHash, 
            sharedNonce: nonce(1003), 
            assetId: dai.id, 
            amount: paymentAmount 
        };
        const aliceChange: Note = { 
            
            ownerHash: alice.ownerHash, 
            sharedNonce: nonce(1004), 
            assetId: usdc.id, 
            amount: offered.amount - listingAmount
        };
        // the order has no amounts or prices in it: alice signs the hashes of her two new notes and of the note that
        // pays for them, whatever is left of that note is the taker's. All or nothing, the order must outlive the proof.
        // Every new note comes with the hash of the message it is announced in, so alice also decides what messages[0]
        // and [1] say. She would encrypt aliceChange and alicePayment to herself there, these tests leave them empty
        const order = swapToadOrder({
            newCommitHashes: [hashNote(aliceChange), hashNote(alicePayment)],
            spendCommitHashes: [hashNote(offered)],
            messageHashes: [MESSAGE_HASHES[0], MESSAGE_HASHES[1]],
            expiry: ts.proof_expire_time_stamp + 3600n,
        });
        const orderSig = signMessage(alice.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));
        // everything alice hands bob. The offered note goes in full, he has to prove it is in the tree: its storage has
        // the key her order is signed with and the secret that nullifies it. With it the owner keys hash its owner hash
        // is made of, the circuit checks the note is owned on this chain. Her two new notes go sealed: the pre
        // commitment hash, asset and amount the circuit reads from a recipient slot. So bob never sees the owner hash
        // or the nonces of what she gets out of the trade, and none of her secrets
        const fromAlice = {
            offered,
            offeredOwnerKeysHash: offerOwner.ownerKeysHash,
            order,
            orderSig,
            change: sealNote(aliceChange),
            payment: sealNote(alicePayment),
        };

        // ---- bob's side: `fromAlice`, his own DAI note and what is on chain. Nothing else of alice's
        const offeredStorage = swapToadStorageOf(fromAlice.offered);
        const localTree = await w.tree();
        const { proof: offeredProof, edgeIndex } = merkleProofInput(localTree, hashNote(fromAlice.offered));
        const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai));
        // he pays what her payment note asks for, and keeps what her change note leaves of the offered one
        const bobChange: Note = { ownerHash: bob.ownerHash, sharedNonce: nonce(2001), assetId: dai.id, amount: bobDai.amount - fromAlice.payment.amount };
        bobUsdc = { ownerHash: bob.ownerHash, sharedNonce: nonce(2002), assetId: usdc.id, amount: fromAlice.offered.amount - fromAlice.change.amount };
        // alice's new notes and her offered note sit in the slots her order names them in, the rest is bob's
        const recipientHashes = [
            hashCommitment(fromAlice.change),
            hashCommitment(fromAlice.payment),
            hashNote(bobChange),
            hashNote(bobUsdc),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: offeredStorage.sharedNullifierSecret, sharedNonce: fromAlice.offered.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: offeredProof.index }),
            hashNullifier({ nullifierSecret: bob.nullifierSecret, sharedNonce: bobDai.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
            hashFakeNullifier({ nonce: nonce(2003) }),
            hashFakeNullifier({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(fromAlice.offered), hashNote(bobDai), 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

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
                recipient_commitments: [
                    sealedRecipientInput(fromAlice.change),
                    sealedRecipientInput(fromAlice.payment),
                    recipientInput(bobChange),
                    recipientInput(bobUsdc),
                ],
                actual_amount_recipient_commitments: 4,
                spend_commitments: [
                    spendInput(fromAlice.offered, usdc.asset, offeredProof, edgeIndex, emptyProof(), fromAlice.offeredOwnerKeysHash),
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
        // the maker's note was built by the taker, so this is the proof it came out spendable
        await unshieldAndUnwrap(w, dai, alicePayment, alice, 3000);
        await unshieldAndUnwrap(w, usdc, bobUsdc, bob, 4000);
        assert.equal(await dai.token.read.balanceOf([alice.wallet.account.address]), DAI("200"));
        assert.equal(await usdc.token.read.balanceOf([bob.wallet.account.address]), USDC("300"));
    });
});
