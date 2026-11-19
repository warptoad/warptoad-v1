/**
 * Every message of a shielded tx is bound to its proof, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it
 *   2. alice proves a transfer to herself with four messages. A relayer that swaps any one of them, a fake slot's
 *      included, gets a verifier revert, and one that drops a message never reaches the verifier. Then the tx as
 *      alice made it goes through
 *
 * The contract hashes each message into the circuit's `message_hashes`, see `Warptoad.formatPublicInputs` and
 * `hashMessages` in src/messages.ts. What the messages say doesn't matter here, the encrypted notes are in
 * ClaudeLilMessaging.test.ts.
 *
 * Needs `pnpm noir` first. Also runs on sepolia, see test/swaptoad.ts:
 *   pnpm hardhat run test/ClaudesLilMessageBinding.test.ts --network sepolia
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import type { Hex } from "viem";
import type { Note } from "../src/types.js";
import { CIRCUIT_SIZE } from "../src/constants.js";
import { hashFakeCommitment, hashFakeNullifier, hashNullifier, hashPublic, type CircuitSizeFields } from "../src/hashing.js";
import { hashMessages } from "../src/messages.js";
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
import { connectSwapToad, privateTx, setupToken, shieldNote, signMessage, USDC, type TokenSide } from "./swaptoad.js";

describe("ClaudesLilMessageBinding", async function () {
    const w = await connectSwapToad();
    const { alice, gigaIndex, nonce } = w;
    let usdc: TokenSide;
    let deposit: Note;

    before(async () => {
        usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("400"));
    });

    after(async () => {
        await w.close();
    });

    it("1. alice shields 400 USDC", async () => {
        deposit = { ownerHash: alice.ownerHash, sharedNonce: nonce(1001), assetId: usdc.id, amount: USDC("400") };
        await shieldNote(w, usdc, deposit, alice.wallet);
        assert.deepEqual((await w.tree()).leaves.slice(-1), [hashNote(deposit)]);
    });

    it("2. a relayer can't swap or drop any of the four messages", async () => {
        const localTree = await w.tree();
        const { proof: depositProof, edgeIndex } = merkleProofInput(localTree, hashNote(deposit));

        // one real new note and three fakes, so slots 1 to 3 carry messages nobody reads
        const kept: Note = { ownerHash: alice.ownerHash, sharedNonce: nonce(2001), assetId: usdc.id, amount: deposit.amount };
        const recipients = [kept, fakeNote(nonce(2002)), fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(kept),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: alice.nullifierSecret, sharedNonce: deposit.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: depositProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
        ] as CircuitSizeFields;
        // any bytes work, the contract only hashes them
        const messages: Hex[] = ["0x01", "0x02", "0x03", "0x04"];
        const messageHashes = hashMessages(messages);
        // what the spender authorizes: every message, unshield, nullifier and new note of this tx. The contract
        // computes the same hash, see `hashPublic`
        const unshielding = [noUnshield(), noUnshield(), noUnshield(), noUnshield()];
        const publicHash = hashPublic({ messageHashes: messageHashes, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
        const sig = signMessage(alice.eddsaKey, publicHash);

        const ts = await w.timeStamps();
        const { proof } = await prove(w.backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: publicHash,
                message_hashes: messageHashes,
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
                    spendInput(deposit, usdc.asset, depositProof, edgeIndex),
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
                auth: noAuth(),
                spend_selectors: joinSplitSelectors(),
            },
        });
        const tx = { ...privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof }), messages };

        // swapping a message changes its entry in message_hashes, a public input the proof was made for. The generated
        // verifier reverts with its own errors instead of returning false, so no VerificationFailed to match on
        for (let slot = 0; slot < CIRCUIT_SIZE; slot++) {
            const swapped = [...messages];
            swapped[slot] = "0xff";
            await assert.rejects(w.warptoad.write.transactPrivate([{ ...tx, messages: swapped }]), `message ${slot} swapped`);
        }
        // and every slot needs one, the contract checks that before it gets to the verifier
        await assert.rejects(w.warptoad.write.transactPrivate([{ ...tx, messages: messages.slice(0, CIRCUIT_SIZE - 1) }]), /WrongCircuitSize/);
        assert.deepEqual((await w.tree()).leaves.slice(-1), [hashNote(deposit)], "nothing got inserted");

        await w.send(w.warptoad.write.transactPrivate([tx]));
        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "alice's deposit is spent");
        assert.deepEqual((await w.tree()).leaves.slice(-4), recipientHashes);
    });
});
