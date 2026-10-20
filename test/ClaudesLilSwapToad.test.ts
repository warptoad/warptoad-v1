/**
 * The two ways a swaptoad lock ends, all on one chain:
 *
 *   1. alice shields 400 USDC into two swaptoad locks, bob shields 500 DAI as a normal note
 *   2. alice cancels the first lock: no order signature, the 400 come back to her as a plain note
 *   3. alice signs an order on the second lock (300 USDC for 200 DAI) and bob fills it: 4 new notes,
 *      bob builds alice's two from the lock's shared secret
 *
 * A lock is a note with circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that
 * signs orders on it plus a shared nullifier secret. The lock is nullified with that secret, not the owner's, so
 * whoever gets the secret with the order can spend the lock, but only the way the order says.
 *
 * Same setup as ClaudesLilHappyPath: no encrypted blobs, secrets just pasted around. Needs `pnpm noir` first
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { Asset, Note } from "../src/types.js";
import { SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashAssetId,
    hashCircuitComponentAuthSig,
    hashFakeCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashOwner,
    hashOwnerKeys,
    hashSharedNonceSwaptoad,
    hashSpendSignatureInputs,
    type CircuitCompStorage,
    type CircuitSizeFields,
} from "../src/hashing.js";
import {
    authSigInputs,
    fakeNote,
    fakeSpendInput,
    hashNote,
    merkleProofInput,
    noAuth,
    noUnshield,
    preCommitmentHashOf,
    prove,
    pubRoots,
    recipientInput,
    spendInput,
    syncedTree,
} from "../src/proving.js";
import { assetOf, encodeWrapperArgs } from "../src/assets.js";
import { publicHashOf } from "../src/messages.js";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { Hex } from "viem";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { deployInfra, deployWarptoad, wrap, ZERO_ADDRESS, type Deployment } from "./fixtures.js";

const NO_MESSAGES: Hex[] = ["0x", "0x", "0x", "0x"];
const { publicHash: PUBLIC_HASH, firstMessageHash: FIRST_MESSAGE_HASH } = publicHashOf(NO_MESSAGES);
const noTarget = { wrapperFactory: ZERO_ADDRESS, wrapperArgs: "0x" as Hex };
const noUnshieldCommitment = { recipient: 0n, amount: 0n, assetId: 0n };
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudesLilSwapToad", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, aliceWallet, bobWallet] = await viem.getWalletClients();

    let d: Deployment;
    let usdc: ContractReturnType<"MockERC20">;
    let dai: ContractReturnType<"MockERC20">;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
    let usdcAsset: Asset;
    let usdcId: bigint;
    let daiAsset: Asset;
    let daiId: bigint;
    const gigaIndex = 0n;

    // alice signs orders with a key of its own, the lock stores its pubkey. Bob never needs one, he only fills
    const alice = {
        eddsaKey: "alice's eddsa key, any bytes work",
        nullifierSecret: 0xa11cen,
        pubKey: { x: 0n, y: 0n },
        ownerKeysHash: 0n,
        ownerHash: 0n,
        orderKey: "alice's swaptoad order key",
        orderPubKey: { x: 0n, y: 0n },
    };
    const bob = {
        eddsaKey: "bob's eddsa key",
        nullifierSecret: 0xb0bn,
        pubKey: { x: 0n, y: 0n },
        ownerKeysHash: 0n,
        ownerHash: 0n,
    };
    for (const who of [alice, bob]) {
        const [x, y] = derivePublicKey(who.eddsaKey);
        who.pubKey = { x, y };
        who.ownerKeysHash = hashOwnerKeys({ spendPubKey: who.pubKey, nullifierSecret: who.nullifierSecret });
        who.ownerHash = hashOwner({ ownerKeysHash: who.ownerKeysHash, gigaIndex });
    }
    {
        const [x, y] = derivePublicKey(alice.orderKey);
        alice.orderPubKey = { x, y };
    }

    // one shared secret per lock: it nullifies the lock and seeds the nonces of the maker's notes on a fill
    const cancelLockSecret = 0x5ec1n;
    const fillLockSecret = 0x5ec2n;
    function lockStorage(sharedNullifierSecret: bigint): CircuitCompStorage {
        return [alice.orderPubKey.x, alice.orderPubKey.y, sharedNullifierSecret];
    }

    let cancelLock: Note;
    let fillLock: Note;
    let bobDai: Note;

    async function tree() {
        const expectedRoot = await d.warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(d.warptoad.address, publicClient, treeId, { expectedRoot });
    }

    async function timeStamps() {
        const now = (await publicClient.getBlock()).timestamp;
        return { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
    }

    before(async () => {
        d = await deployWarptoad(viem, await deployInfra(viem, publicClient, deployer));
        assert.equal(d.gigaIndex, gigaIndex, "the local chain config puts hardhat at giga index 0");
        treeId = await d.warptoad.read.commitmentTreeId();

        usdc = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
        await usdc.write.mint([aliceWallet.account.address, 1000n]);
        await usdc.write.approve([d.factory.address, 1000n], { account: aliceWallet.account });
        dai = await viem.deployContract("MockERC20", ["Dai Stablecoin", "DAI", 18]);
        await dai.write.mint([bobWallet.account.address, 1000n]);
        await dai.write.approve([d.factory.address, 1000n], { account: bobWallet.account });

        bb = await Barretenberg.new({ threads: cpus().length });
        backend = new UltraHonkBackend(circuit.bytecode, bb);
    });

    after(async () => {
        await bb.destroy();
    });

    it("1. alice locks 400 USDC twice, bob shields 500 DAI", async () => {
        const usdcWrapper = await wrap(viem, d, usdc.address, 1000n, aliceWallet.account.address, aliceWallet.account.address);
        const daiWrapper = await wrap(viem, d, dai.address, 1000n, bobWallet.account.address, bobWallet.account.address);
        const [firstGigaIndex, lastGigaIndex] = await d.factory.read.gigaIndexRange();
        usdcAsset = assetOf({ wrapperFactory: d.factory.address, wrapper: usdcWrapper.address, underlying: usdc.address, firstGigaIndex, lastGigaIndex });
        daiAsset = assetOf({ wrapperFactory: d.factory.address, wrapper: daiWrapper.address, underlying: dai.address, firstGigaIndex, lastGigaIndex });
        usdcId = hashAssetId(usdcAsset);
        daiId = hashAssetId(daiAsset);

        cancelLock = {
            ownerHash: alice.ownerHash,
            sharedNonce: 1001n,
            assetId: usdcId,
            amount: 400n,
            circuitCompSelector: SWAP_TOAD_SELECTOR,
            circuitCompStorage: lockStorage(cancelLockSecret),
        };
        fillLock = { ...cancelLock, sharedNonce: 1002n, circuitCompStorage: lockStorage(fillLockSecret) };
        bobDai = { ownerHash: bob.ownerHash, sharedNonce: 1003n, assetId: daiId, amount: 500n };

        // shield takes any pre_commitment_hash, so a lock can be made straight from a wrapper balance
        const usdcArgs = encodeWrapperArgs({ wrapper: usdcWrapper.address, underlying: usdc.address });
        for (const lock of [cancelLock, fillLock]) {
            await d.warptoad.write.shield([d.factory.address, preCommitmentHashOf(lock), lock.amount, usdcArgs, "0x"], { account: aliceWallet.account });
        }
        const daiArgs = encodeWrapperArgs({ wrapper: daiWrapper.address, underlying: dai.address });
        await d.warptoad.write.shield([d.factory.address, preCommitmentHashOf(bobDai), 500n, daiArgs, "0x"], { account: bobWallet.account });

        assert.equal(await usdcWrapper.read.balanceOf([aliceWallet.account.address]), 200n);
        assert.equal(await daiWrapper.read.balanceOf([bobWallet.account.address]), 500n);
        assert.deepEqual((await tree()).leaves, [cancelLock, fillLock, bobDai].map(hashNote));
    });

    it("2. alice cancels a lock without an order signature, the 400 come back as a plain note", async () => {
        const localTree = await tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(cancelLock));

        // the only real new note: same asset and amount as the lock, the circuit checks nothing else about it
        const refund: Note = { ownerHash: alice.ownerHash, sharedNonce: 2001n, assetId: usdcId, amount: 400n };
        const recipients = [refund, fakeNote(2002n), fakeNote(2003n), fakeNote(2004n)];
        const recipientHashes = [
            hashNote(refund),
            hashFakeCommitment({ nonce: 2002n }),
            hashFakeCommitment({ nonce: 2003n }),
            hashFakeCommitment({ nonce: 2004n }),
        ] as CircuitSizeFields;
        // the lock is nullified with its shared secret, not alice's own, so a cancel and a fill spend the same nullifier
        const nullifiers = [
            hashNullifier({ nullifierSecret: cancelLockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashFakeNullifier({ nonce: 2005n }),
            hashFakeNullifier({ nonce: 2006n }),
            hashFakeNullifier({ nonce: 2007n }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(cancelLock), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(alice.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
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
                    spendInput(cancelLock, usdcAsset, lockProof, edgeIndex),
                    fakeSpendInput(2005n),
                    fakeSpendInput(2006n),
                    fakeSpendInput(2007n),
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

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment],
            unshieldTargets: [noTarget, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages: NO_MESSAGES,
            publicHash: PUBLIC_HASH,
            proof,
        };
        await d.warptoad.write.transactPrivate([tx]);

        assert.equal(await d.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.deepEqual((await tree()).leaves, [...localTree.leaves, ...recipientHashes]);
    });

    it("3. bob fills alice's order: 300 of the locked USDC for 200 DAI", async () => {
        const localTree = await tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(fillLock));
        const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai));
        const ts = await timeStamps();

        // ---- alice's side, all of it before bob shows up: the order, and the two notes bob will make for her.
        // their nonces come from the lock's secret so bob can't pick them, type 0 is the payment, 1 the change
        const alicePayment: Note = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: fillLockSecret, commitmentType: 0n }),
            assetId: daiId,
            amount: 200n,
        };
        const aliceChange: Note = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: fillLockSecret, commitmentType: 1n }),
            assetId: usdcId,
            amount: 100n,
        };
        // `SwapToadOrder` in circuits/src/main.nr, in the order the maker signs it. The order must outlive the proof.
        // first_message_hash pins messages[0] and [1], where the notes for aliceChange and alicePayment would go.
        // The owner keys hash is what lets the circuit check the lock is on this chain's giga index
        const order = authSigInputs([
            usdcId,
            300n,
            daiId,
            200n,
            ts.proof_expire_time_stamp + 3600n,
            FIRST_MESSAGE_HASH,
            preCommitmentHashOf(aliceChange),
            alice.ownerKeysHash,
        ]);
        const orderSig = signMessage(alice.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));

        // ---- bob's side: alice handed him the order, its signature and fillLockSecret
        const bobChange: Note = { ownerHash: bob.ownerHash, sharedNonce: 3001n, assetId: daiId, amount: 300n };
        const bobUsdc: Note = { ownerHash: bob.ownerHash, sharedNonce: 3002n, assetId: usdcId, amount: 300n };
        // slot order is fixed by the circuit: maker change, maker payment, taker change, taker payment
        const recipients = [aliceChange, alicePayment, bobChange, bobUsdc];
        const recipientHashes = recipients.map(hashNote) as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: fillLockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashNullifier({ nullifierSecret: bob.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
            hashFakeNullifier({ nonce: 3003n }),
            hashFakeNullifier({ nonce: 3004n }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(fillLock), hashNote(bobDai), 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

        const { proof } = await prove(backend, circuit as CompiledCircuit, {
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
                    spendInput(fillLock, usdcAsset, lockProof, edgeIndex),
                    spendInput(bobDai, daiAsset, daiProof, edgeIndex),
                    fakeSpendInput(3003n),
                    fakeSpendInput(3004n),
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

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment],
            unshieldTargets: [noTarget, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages: NO_MESSAGES,
            publicHash: PUBLIC_HASH,
            proof,
        };
        await d.warptoad.write.transactPrivate([tx]);

        assert.equal(await d.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.equal(await d.warptoad.read.nullifiers([nullifiers[1]]) > 0n, true, "bob's DAI note is spent");
        assert.deepEqual((await tree()).leaves, [...localTree.leaves, ...recipientHashes]);
        // the lock can't be filled twice
        await assert.rejects(d.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });
});
