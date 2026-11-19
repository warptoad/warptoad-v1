/**
 * A prover that is not the signer can't change what the signer authorized, all on one chain:
 *
 *   1. alice wraps 400 USDC and shields it
 *   2. alice signs an unshield of it to her own address and hands the signature to a prover, the way a hardware
 *      wallet would. The prover has every private input, her nullifier secret included, but not her spend key.
 *      It can't redirect the unshield to itself and it can't swap a message. Then the tx as alice signed it goes
 *      through
 *
 * The spend signature is made over `public_hash`, and the contract computes that itself from what the tx does:
 * message hashes, unshielding commitments, nullifiers and recipient commitment hashes, see
 * `Warptoad.formatPublicInputs` and `hashPublic` in src/hashing.ts. So a prover either proves with the hash of the
 * changed tx, and the signature is not for it, or with the hash alice signed, and the contract's hash differs.
 *
 * Needs `pnpm noir` first. Also runs on sepolia, see test/swaptoad.ts:
 *   pnpm hardhat run test/ClaudesLilDelegatedProver.test.ts --network sepolia
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import type { Address, Hex } from "viem";
import type { Note } from "../src/types.js";
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
    unshieldInput,
} from "../src/proving.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { connectSwapToad, privateTx, setupToken, shieldNote, signMessage, USDC, type TokenSide } from "./swaptoad.js";

describe("ClaudesLilDelegatedProver", async function () {
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

    it("2. a prover holding alice's signature can't redirect her unshield or swap a message", async () => {
        const localTree = await w.tree();
        const { proof: depositProof, edgeIndex } = merkleProofInput(localTree, hashNote(deposit));
        const ts = await w.timeStamps();
        const aliceAddress = alice.wallet.account.address;
        const proverAddress = w.deployer.account.address;

        // the unshield alice wants: all 400 to her own address. An unshield is a recipient note whose owner hash is the address
        const unshieldNote: Note = { ownerHash: BigInt(aliceAddress), sharedNonce: 0n, assetId: deposit.assetId, amount: deposit.amount };
        const recipients = [unshieldNote, fakeNote(nonce(2001)), fakeNote(nonce(2002)), fakeNote(nonce(2003))];
        const recipientHashes = [
            hashNote(unshieldNote),
            hashFakeCommitment({ nonce: nonce(2001) }),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: alice.nullifierSecret, sharedNonce: deposit.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: depositProof.index }),
            hashFakeNullifier({ nonce: nonce(2004) }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
        ] as CircuitSizeFields;
        // any bytes work, the contract only hashes them
        const messages: Hex[] = ["0x01", "0x02", "0x03", "0x04"];

        /** the parts of the tx a prover could try to change, and the `public_hash` the contract computes for them */
        function publicSide(unshieldTo: Address, messagesSent: Hex[]) {
            const unshielding = [unshieldInput(unshieldTo, deposit.assetId, deposit.amount), noUnshield(), noUnshield(), noUnshield()];
            const messageHashes = hashMessages(messagesSent);
            const publicHash = hashPublic({ messageHashes, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
            return { unshieldTo, messagesSent, unshielding, messageHashes, publicHash };
        }

        // ---- alice's side: she signs the hash of what she wants done. Only the signature leaves her signing device
        const wanted = publicSide(aliceAddress, messages);
        const sig = signMessage(alice.eddsaKey, wanted.publicHash);

        // ---- the prover's side: alice's signature and every private input, but not her spend key
        function proveWith(side: ReturnType<typeof publicSide>, publicHash: bigint) {
            return prove(w.backend, circuit as CompiledCircuit, {
                pub_in: {
                    roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                    time_stamps: ts,
                    public_hash: publicHash,
                    message_hashes: side.messageHashes,
                    unshielding_commitments: side.unshielding,
                    nullifiers,
                    recipient_commitments_hashes: recipientHashes,
                },
                priv_in: {
                    // the circuit only compares the address unshielded to with `owner_hash` of the slot, so that is all
                    // a prover has to change to send the funds somewhere else. The commitment hash stays alice's
                    recipient_commitments: recipients.map(function (n, slot) {
                        return slot === 0 ? { ...recipientInput(n), owner_hash: BigInt(side.unshieldTo) } : recipientInput(n);
                    }),
                    actual_amount_recipient_commitments: 1,
                    spend_commitments: [
                        spendInput(deposit, usdc.asset, depositProof, edgeIndex),
                        fakeSpendInput(nonce(2004)),
                        fakeSpendInput(nonce(2005)),
                        fakeSpendInput(nonce(2006)),
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
        }
        function txOf(side: ReturnType<typeof publicSide>, proof: Hex) {
            const unshield = { recipient: side.unshieldTo, note: unshieldNote, side: usdc };
            return { ...privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof, unshield }), messages: side.messagesSent };
        }

        // with the public hash of the changed tx, alice's signature is not for it
        const redirected = publicSide(proverAddress, messages);
        await assert.rejects(proveWith(redirected, redirected.publicHash), /invalid spend signature/);
        const swapped = publicSide(aliceAddress, ["0xff", ...messages.slice(1)]);
        await assert.rejects(proveWith(swapped, swapped.publicHash), /invalid spend signature/);

        // with the public hash alice did sign the prover gets a proof, but the contract computes the hash from what the
        // tx really does. The generated verifier reverts with its own errors, so no VerificationFailed to match on
        const { proof: redirectedProof } = await proveWith(redirected, wanted.publicHash);
        await assert.rejects(w.warptoad.write.transactPrivate([txOf(redirected, redirectedProof)]));
        const { proof: swappedProof } = await proveWith(swapped, wanted.publicHash);
        await assert.rejects(w.warptoad.write.transactPrivate([txOf(swapped, swappedProof)]));
        assert.equal(await usdc.wrapper.read.balanceOf([proverAddress]), 0n, "the prover got nothing");

        // the tx alice signed goes through, whoever proves it
        const { proof } = await proveWith(wanted, wanted.publicHash);
        const before = await usdc.wrapper.read.balanceOf([aliceAddress]);
        await w.send(w.warptoad.write.transactPrivate([txOf(wanted, proof)]));
        assert.equal(await usdc.wrapper.read.balanceOf([aliceAddress]), before + deposit.amount, "unshielded to alice");
        assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "alice's deposit is spent");
    });
});
