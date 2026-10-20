/**
 * The simplest possible end to end run of the main circuit, all on one chain:
 *
 *   1. alice wraps USDC through the factory and shields 400 of it
 *   2. alice sends bob 300 shielded, keeps 100 as change
 *   3. bob unshields his 300 back into wrapped USDC
 *
 * Witness with noir_js, proof with bb.js, tree synced with skinny-fat-imt-js, secrets just pasted
 * around. No utxo management, no encrypted blobs, bob "just knows" what alice sent him, asset preimage included.
 *
 * Needs `pnpm noir` first: the circuit json comes from circuits/target and the verifier from contracts/.
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { Asset, Note, WrapperERC20Contract } from "../src/types.js";
import { CIRCUIT_COMP_STORAGE_EMPTY_HASH, JOIN_SPLIT_SELECTOR } from "../src/constants.js";
import {
    hashAssetId,
    hashFakeCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashOwner,
    hashOwnerKeys,
    hashPreCommitment,
    hashSpendSignatureInputs,
    type CircuitSizeFields,
} from "../src/hashing.js";
import {
    fakeNote,
    fakeSpendInput,
    merkleProofInput,
    noAuth,
    hashNote,
    noUnshield,
    preCommitmentHashOf,
    prove,
    pubRoots,
    recipientInput,
    spendInput,
    syncedTree,
    unshieldInput,
} from "../src/proving.js";
import { assetOf, encodeWrapperArgs } from "../src/assets.js";
import { publicHashOf } from "../src/messages.js";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { Hex } from "viem";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { deployInfra, deployWarptoad, wrap, ZERO_ADDRESS, type Deployment } from "./fixtures.js";

// no encrypted blobs here, but the contract always hashes the first two messages into first_message_hash,
// and public_hash goes in the spend signature. See ClaudeLilMessaging.test.ts
const NO_MESSAGES: Hex[] = ["0x", "0x", "0x", "0x"];
const { publicHash: PUBLIC_HASH, firstMessageHash: FIRST_MESSAGE_HASH } = publicHashOf(NO_MESSAGES);
const noTarget = { wrapperFactory: ZERO_ADDRESS, wrapperArgs: "0x" as Hex };
// the esm build of eddsa-poseidon trips over blakejs' cjs exports under node, the cjs build is fine
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudesLilHappyPath", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, aliceWallet, bobWallet] = await viem.getWalletClients();

    let d: Deployment;
    let token: ContractReturnType<"MockERC20">;
    let wrapper: WrapperERC20Contract;
    let wrapperArgs: Hex;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
    /** the preimage every spend needs, and its hash that every note carries */
    let asset: Asset;
    let assetId: bigint;
    const gigaIndex = 0n;

    // secrets, just pasted around
    const alice = {
        eddsaKey: "alice's eddsa key, any bytes work",
        nullifierSecret: 0xa11cen,
        pubKey: { x: 0n, y: 0n },
        ownerHash: 0n,
    };
    const bob = {
        eddsaKey: "bob's eddsa key",
        nullifierSecret: 0xb0bn,
        pubKey: { x: 0n, y: 0n },
        ownerHash: 0n,
    };
    for (const who of [alice, bob]) {
        const [x, y] = derivePublicKey(who.eddsaKey);
        who.pubKey = { x, y };
        const ownerKeysHash = hashOwnerKeys({ spendPubKey: who.pubKey, nullifierSecret: who.nullifierSecret });
        who.ownerHash = hashOwner({ ownerKeysHash, gigaIndex });
    }

    // the notes that exist during the story
    let aliceDeposit: Note;
    let bobNote: Note;
    let aliceChange: Note;

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

        token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
        await token.write.mint([aliceWallet.account.address, 1000n]);
        await token.write.approve([d.factory.address, 1000n], { account: aliceWallet.account });

        bb = await Barretenberg.new({ threads: cpus().length });
        backend = new UltraHonkBackend(circuit.bytecode, bb);
    });

    after(async () => {
        await bb.destroy();
    });

    it("1. alice wraps and shields 400", async () => {
        wrapper = await wrap(viem, d,token.address, 1000n, aliceWallet.account.address, aliceWallet.account.address);
        wrapperArgs = encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address });
        const [firstGigaIndex, lastGigaIndex] = await d.factory.read.gigaIndexRange();
        asset = assetOf({ wrapperFactory: d.factory.address, wrapper: wrapper.address, underlying: token.address, firstGigaIndex, lastGigaIndex });
        assetId = hashAssetId(asset);

        aliceDeposit = { ownerHash: alice.ownerHash, sharedNonce: 1001n, assetId, amount: 400n };
        const preCommitmentHash = hashPreCommitment({
            ownerHash: alice.ownerHash,
            sharedNonce: aliceDeposit.sharedNonce,
            circuitCompSelector: JOIN_SPLIT_SELECTOR,
            circuitCompStorageHash: CIRCUIT_COMP_STORAGE_EMPTY_HASH,
        });
        assert.equal(preCommitmentHash, preCommitmentHashOf(aliceDeposit));
        await d.warptoad.write.shield([d.factory.address, preCommitmentHash, 400n, wrapperArgs, "0x"], { account: aliceWallet.account });

        assert.equal(await wrapper.read.balanceOf([aliceWallet.account.address]), 600n);
        assert.deepEqual((await tree()).leaves, [hashNote(aliceDeposit)]);
    });

    it("2. alice sends bob 300 shielded, 100 change", async () => {
        const localTree = await tree();
        const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(aliceDeposit));

        bobNote = { ownerHash: bob.ownerHash, sharedNonce: 2001n, assetId, amount: 300n };
        aliceChange = { ownerHash: alice.ownerHash, sharedNonce: 2002n, assetId, amount: 100n };
        const recipients = [bobNote, aliceChange, fakeNote(2003n), fakeNote(2004n)];

        const recipientHashes = [
            hashNote(bobNote),
            hashNote(aliceChange),
            hashFakeCommitment({ nonce: 2003n }),
            hashFakeCommitment({ nonce: 2004n }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: alice.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
            hashFakeNullifier({ nonce: 2005n }),
            hashFakeNullifier({ nonce: 2006n }),
            hashFakeNullifier({ nonce: 2007n }),
        ] as CircuitSizeFields;
        // fake spend slots hash to 0 inside the circuit
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(aliceDeposit), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(alice.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof, publicInputs } = await prove(backend, circuit as CompiledCircuit, {
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
                actual_amount_recipient_commitments: 2,
                spend_commitments: [
                    spendInput(aliceDeposit, asset, localProof, edgeIndex),
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
                auth: noAuth(),
                circuit_comp_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [0, 1, 2, 3].map(function () {
                return { recipient: 0n, amount: 0n, assetId: 0n };
            }),
            unshieldTargets: [noTarget, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages: NO_MESSAGES,
            publicHash: PUBLIC_HASH,
            proof,
        };
        // the contract lays public inputs out the same way bb did, and hashes the first two messages the same way the sdk does
        assert.equal(await d.warptoad.read.hashMessages([NO_MESSAGES[0], NO_MESSAGES[1]]), FIRST_MESSAGE_HASH);
        const formatted = await d.warptoad.read.formatPublicInputs([
            tx.roots, tx.timeStamps, FIRST_MESSAGE_HASH, PUBLIC_HASH, tx.unshieldingCommitments, tx.nullifiers, tx.recipientCommitmentsHashes, gigaIndex,
        ]);
        assert.deepEqual(
            formatted.map(function (x) {
                return BigInt(x);
            }),
            publicInputs,
        );

        // anyone can relay it, deployer does here
        await d.warptoad.write.transactPrivate([tx]);

        assert.equal(await d.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "alice's deposit is spent");
        assert.deepEqual((await tree()).leaves, [hashNote(aliceDeposit), ...recipientHashes]);
    });

    it("3. bob unshields his 300", async () => {
        const localTree = await tree();
        const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(bobNote));

        // an unshield is a recipient note whose owner hash is bob's eth address, in slot 0
        const bobAddress = bobWallet.account.address;
        const unshieldNote: Note = { ownerHash: BigInt(bobAddress), sharedNonce: 0n, assetId, amount: 300n };
        const recipients = [unshieldNote, fakeNote(3001n), fakeNote(3002n), fakeNote(3003n)];

        const recipientHashes = [
            hashNote(unshieldNote),
            hashFakeCommitment({ nonce: 3001n }),
            hashFakeCommitment({ nonce: 3002n }),
            hashFakeCommitment({ nonce: 3003n }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: bob.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
            hashFakeNullifier({ nonce: 3004n }),
            hashFakeNullifier({ nonce: 3005n }),
            hashFakeNullifier({ nonce: 3006n }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(bobNote), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: PUBLIC_HASH,
                first_message_hash: FIRST_MESSAGE_HASH,
                unshielding_commitments: [unshieldInput(bobAddress, assetId, 300n), noUnshield(), noUnshield(), noUnshield()],
                nullifiers,
                recipient_commitments_hashes: recipientHashes,
            },
            priv_in: {
                recipient_commitments: recipients.map(function (n) {
                    return recipientInput(n);
                }),
                actual_amount_recipient_commitments: 1,
                spend_commitments: [
                    spendInput(bobNote, asset, localProof, edgeIndex),
                    fakeSpendInput(3004n),
                    fakeSpendInput(3005n),
                    fakeSpendInput(3006n),
                ],
                actual_amount_spend_commitments: 1,
                owner: {
                    pub_key: bob.pubKey,
                    nullifier_secret: bob.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                auth: noAuth(),
                circuit_comp_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [
                { recipient: BigInt(bobAddress), amount: 300n, assetId },
                { recipient: 0n, amount: 0n, assetId: 0n },
                { recipient: 0n, amount: 0n, assetId: 0n },
                { recipient: 0n, amount: 0n, assetId: 0n },
            ],
            // the wrapper exists on this chain, so the short args are enough. See ClaudeLilMessaging for the long ones
            unshieldTargets: [{ wrapperFactory: d.factory.address, wrapperArgs }, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages: NO_MESSAGES,
            publicHash: PUBLIC_HASH,
            proof,
        };
        await d.warptoad.write.transactPrivate([tx]);

        assert.equal(await wrapper.read.balanceOf([bobAddress]), 300n, "bob got his wrapped USDC");
        // the unshield note stayed out of the tree, the 3 fakes went in
        const after = await tree();
        assert.equal(after.size, 5 + 3);
        assert.equal(after.indexOf(hashNote(unshieldNote)), -1);

        // and bob can't do it twice
        await assert.rejects(d.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });
});
