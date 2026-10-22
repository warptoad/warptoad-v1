/**
 * The happy path again, but bob no longer "just knows" what alice sent him:
 *
 *   1. alice wraps 1000 and shields 400 to herself, with a note encrypted to her own view key
 *   2. alice sends bob 300 and 100 change, one encrypted note per slot, fakes get garbage.
 *      A relayer that swaps one of the first two messages gets a verifier revert, those are in first_message_hash
 *   3. bob and alice scan every Message event and find exactly their own notes. Bob turns the assetId in his
 *      note back into the asset preimage and the wrapper with eth_calls only, see src/assets.ts
 *   4. bob unshields the note he found into wrapped USDC and unwraps it into the real thing
 *
 * So the full round trip: wrap, shield, shielded tx to bob, unshield, unwrap
 *
 * Needs `pnpm noir` first, same as ClaudesLilHappyPath
 *
 * Also runs against a real deployment, sending the same txs on chain (see README, Deploy):
 *   pnpm hardhat run test/ClaudeLilMessaging.test.ts --network sepolia
 * `run` and not `test`: the test task refuses to unlock the password protected keystore, `run` prompts for it.
 * Warptoad, the factory and the verifier come from ignition/deployments/chain-<id>/, only a MockERC20 gets deployed.
 * Alice and bob are the second and third configured accounts (the deployer tops them up with gas), and nonces are
 * randomised so reruns don't collide
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { Asset, Note, WarptoadContract, WrapperERC20Contract, WrapperFactoryContract } from "../src/types.js";
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
    prove,
    pubRoots,
    recipientInput,
    spendInput,
    syncedTree,
    unshieldInput,
} from "../src/proving.js";
import { assetOf, encodeWrapperArgs, encodeWrapperDeployArgs, resolveAsset } from "../src/assets.js";
import { decryptNote, deriveViewKey, encryptNote, fakeMessage, getAllNotes, publicHashOf } from "../src/messages.js";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { getAddress, type Address, type Hex } from "viem";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { deployInfra, deployWarptoad, fundIfLow, wrap, ZERO_ADDRESS } from "./fixtures.js";

const noUnshieldCommitment = { recipient: 0n, amount: 0n, assetId: 0n };
const noTarget = { wrapperFactory: ZERO_ADDRESS, wrapperArgs: "0x" as Hex };
/** MockERC20 ("USD Coin", "USDC", 6) to reuse on a live chain, anyone can mint it. A chain not in here gets a fresh one */
const MOCK_ERC20: Record<number, Address> = {
    11155111: "0x5afC539F572A1C4CF4c7FcC4ef3169c232F9c0E4",
};
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudeLilMessaging", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    // the live network config has three keys, see hardhat.config.ts. A config with fewer falls back to the deployer
    const [deployer, aliceWallet = deployer, bobWallet = deployer] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();
    const live = chainId !== 31337;
    // fake nullifiers and commitments are hashes of these, so on a live chain every run needs fresh ones
    const nonceBase = live ? BigInt(Date.now()) << 16n : 0n;
    function nonce(i: number) {
        return nonceBase + BigInt(i);
    }
    // hardhat-viem's write returns as soon as the tx is sent, a live chain needs the receipt before the next step
    async function send(tx: Promise<Hex>) {
        const hash = await tx;
        if (live) await publicClient.waitForTransactionReceipt({ hash });
        return hash;
    }
    // a live contract has notes and leaves from earlier runs, only look at this run's
    let scanFromBlock = 0n;

    let warptoad: WarptoadContract;
    let factory: WrapperFactoryContract;
    let token: ContractReturnType<"MockERC20">;
    let wrapper: WrapperERC20Contract;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
    let gigaIndex: bigint;
    let asset: Asset;
    let assetId: bigint;

    // one secret each, the view key is derived from it. Alice only ever learns bob's ownerHash and view public key
    const alice = {
        eddsaKey: "alice's eddsa key, any bytes work",
        nullifierSecret: 0xa11cen,
        pubKey: { x: 0n, y: 0n },
        ownerHash: 0n,
        view: deriveViewKey("alice's eddsa key, any bytes work"),
    };
    const bob = {
        eddsaKey: "bob's eddsa key",
        nullifierSecret: 0xb0bn,
        pubKey: { x: 0n, y: 0n },
        ownerHash: 0n,
        view: deriveViewKey("bob's eddsa key"),
    };

    let aliceDeposit: Note;
    let bobNote: Note;
    let aliceChange: Note;

    async function tree() {
        const expectedRoot = await warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(warptoad.address, publicClient, treeId, { expectedRoot });
    }

    before(async () => {
        if (live) {
            scanFromBlock = await publicClient.getBlockNumber();
            const deployed = JSON.parse(await readFile(`ignition/deployments/chain-${chainId}/deployed_addresses.json`, "utf8"));
            warptoad = await viem.getContractAt("Warptoad", deployed["Warptoad#Warptoad"]);
            factory = await viem.getContractAt("WrapperFactory", deployed["Warptoad#WrapperFactory"]);
            await fundIfLow(publicClient, deployer, aliceWallet.account.address);
            await fundIfLow(publicClient, deployer, bobWallet.account.address);
        } else {
            ({ warptoad, factory } = await deployWarptoad(viem, await deployInfra(viem, publicClient, deployer)));
        }
        treeId = await warptoad.read.commitmentTreeId();
        // owner hashes are bound to the chain they can be spent on, so they wait for the contract's giga index
        gigaIndex = BigInt(await warptoad.read.gigaIndex());
        for (const who of [alice, bob]) {
            const [x, y] = derivePublicKey(who.eddsaKey);
            who.pubKey = { x, y };
            const ownerKeysHash = hashOwnerKeys({ spendPubKey: who.pubKey, nullifierSecret: who.nullifierSecret });
            who.ownerHash = hashOwner({ ownerKeysHash, gigaIndex });
        }

        const mockAddress = MOCK_ERC20[chainId];
        if (mockAddress !== undefined) {
            token = await viem.getContractAt("MockERC20", mockAddress);
        } else {
            token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            if (live) console.log(`deployed MockERC20 at ${token.address}, add it to MOCK_ERC20 to reuse it`);
        }
        await send(token.write.mint([aliceWallet.account.address, 1000n]));
        await send(token.write.approve([factory.address, 1000n], { account: aliceWallet.account }));

        bb = await Barretenberg.new({ threads: cpus().length });
        backend = new UltraHonkBackend(circuit.bytecode, bb);
    });

    after(async () => {
        await bb.destroy();
    });

    it("0. a note round trips, and only through the right key", async () => {
        const note: Note = { ownerHash: bob.ownerHash, sharedNonce: 7n, assetId: 8n, amount: 9n };
        const message = await encryptNote(note, bob.view.publicKey);
        assert.deepEqual(await decryptNote(message, bob.view.privateKey), { ...note, ...recipientDefaults() });
        assert.equal(await decryptNote(message, alice.view.privateKey), null);
        assert.equal(await decryptNote(await fakeMessage(1n), bob.view.privateKey), null);
        // the tag slot is there, still zero
        assert.equal(message.slice(4, 4 + 64), "0".repeat(64));
        // and a tiny note is as long as a huge one
        const huge: Note = { ...note, ownerHash: (1n << 254n) - 1n, amount: (1n << 254n) - 1n };
        assert.equal((await encryptNote(huge, bob.view.publicKey)).length, message.length);
    });

    it("1. alice wraps and shields 400, with a note to herself", async () => {
        wrapper = await wrap(viem, { factory, gigaIndex },token.address, 1000n, aliceWallet.account.address, aliceWallet.account.address);
        const [firstGigaIndex, lastGigaIndex] = await factory.read.gigaIndexRange();
        asset = assetOf({ wrapperFactory: factory.address, wrapper: wrapper.address, underlying: token.address, firstGigaIndex, lastGigaIndex });
        assetId = hashAssetId(asset);

        aliceDeposit = { ownerHash: alice.ownerHash, sharedNonce: nonce(1001), assetId, amount: 400n };
        const preCommitmentHash = hashPreCommitment({
            ownerHash: alice.ownerHash,
            sharedNonce: aliceDeposit.sharedNonce,
            circuitCompSelector: JOIN_SPLIT_SELECTOR,
            circuitCompStorageHash: CIRCUIT_COMP_STORAGE_EMPTY_HASH,
        });
        const message = await encryptNote(aliceDeposit, alice.view.publicKey);
        const wrapperArgs = encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address });
        await send(warptoad.write.shield([factory.address, preCommitmentHash, 400n, wrapperArgs, message], { account: aliceWallet.account }));

        assert.deepEqual((await tree()).leaves.slice(-1), [hashNote(aliceDeposit)]);
        assert.deepEqual(await getAllNotes(warptoad, publicClient, alice.view.privateKey, { fromBlock: scanFromBlock }), [
            { ...aliceDeposit, ...recipientDefaults() },
        ]);
    });

    it("2. alice sends bob 300 and 100 change, messages included, relayer can't touch the first two", async () => {
        const localTree = await tree();
        const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(aliceDeposit));

        bobNote = { ownerHash: bob.ownerHash, sharedNonce: nonce(2001), assetId, amount: 300n };
        aliceChange = { ownerHash: alice.ownerHash, sharedNonce: nonce(2002), assetId, amount: 100n };
        const recipients = [bobNote, aliceChange, fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(bobNote),
            hashNote(aliceChange),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: alice.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
        ] as CircuitSizeFields;

        // one message per slot, the fakes get one nobody can open
        const messages: Hex[] = [
            await encryptNote(bobNote, bob.view.publicKey),
            await encryptNote(aliceChange, alice.view.publicKey),
            await fakeMessage(nonce(2003)),
            await fakeMessage(nonce(2004)),
        ];
        const { publicHash, firstMessageHash } = publicHashOf(messages);

        const sigHash = hashSpendSignatureInputs({
            publicHash,
            spendCommitmentHashes: [hashNote(aliceDeposit), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(alice.eddsaKey, sigHash);

        const now = (await publicClient.getBlock()).timestamp;
        const ts = { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: publicHash,
                first_message_hash: firstMessageHash,
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
                circuit_comp_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment],
            unshieldTargets: [noTarget, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages,
            publicHash,
            proof,
        };
        assert.equal(await warptoad.read.hashMessages([messages[0], messages[1]]), firstMessageHash);

        // a relayer swapping bob's message for garbage changes first_message_hash, a public input the proof was made for.
        // Only the first two messages are hashed by the contract, the other two are not bound to the proof.
        // The generated verifier reverts with its own errors instead of returning false, so no VerificationFailed to match on
        const tampered = { ...tx, messages: [await fakeMessage(666n), ...messages.slice(1)] };
        await assert.rejects(warptoad.write.transactPrivate([tampered]));
        assert.deepEqual((await tree()).leaves.slice(-1), [hashNote(aliceDeposit)], "nothing got inserted");

        await send(warptoad.write.transactPrivate([tx]));
        assert.deepEqual((await tree()).leaves.slice(-5), [hashNote(aliceDeposit), ...recipientHashes]);
    });

    it("3. bob and alice find their notes by scanning the Message events, bob resolves the asset", async () => {
        const bobNotes = await getAllNotes(warptoad, publicClient, bob.view.privateKey, { fromBlock: scanFromBlock });
        assert.deepEqual(bobNotes, [{ ...bobNote, ...recipientDefaults() }]);

        const aliceNotes = await getAllNotes(warptoad, publicClient, alice.view.privateKey, { fromBlock: scanFromBlock });
        assert.deepEqual(aliceNotes, [aliceDeposit, aliceChange].map(function (n) {
            return { ...n, ...recipientDefaults() };
        }));

        // and what bob found is really a leaf he can spend from
        const localTree = await tree();
        assert.notEqual(localTree.indexOf(hashNote(bobNotes[0])), -1);

        // all bob has is the assetId. The contracts hand back everything he needs to spend and unshield it
        const resolved = await resolveAsset(warptoad, publicClient, bobNotes[0].assetId);
        assert.deepEqual(resolved.asset, asset);
        assert.equal(getAddress(resolved.wrapperFactory), getAddress(factory.address));
        assert.equal(getAddress(resolved.wrapper), getAddress(wrapper.address));
        assert.equal(getAddress(resolved.deployInfo.underlying), getAddress(token.address));
        assert.equal(resolved.deployInfo.originGigaIndex, gigaIndex);
    });

    it("4. bob unshields his 300 into wrapped USDC and unwraps it", async () => {
        const localTree = await tree();
        const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(bobNote));
        // bob works from what step 3 resolved, not from alice's variables
        const { asset: bobAsset, wrapperFactory, wrapper: bobWrapper, deployInfo } = await resolveAsset(warptoad, publicClient, bobNote.assetId);

        // an unshield is a recipient note whose owner hash is bob's eth address, unshields have to come first
        const bobAddress = bobWallet.account.address;
        const unshieldNote: Note = { ownerHash: BigInt(bobAddress), sharedNonce: 0n, assetId, amount: 300n };
        const recipients = [unshieldNote, fakeNote(nonce(3001)), fakeNote(nonce(3002)), fakeNote(nonce(3003))];
        const recipientHashes = [
            hashNote(unshieldNote),
            hashFakeCommitment({ nonce: nonce(3001) }),
            hashFakeCommitment({ nonce: nonce(3002) }),
            hashFakeCommitment({ nonce: nonce(3003) }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: bob.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
            hashFakeNullifier({ nonce: nonce(3004) }),
            hashFakeNullifier({ nonce: nonce(3005) }),
            hashFakeNullifier({ nonce: nonce(3006) }),
        ] as CircuitSizeFields;

        // nothing to tell anyone here, but every slot still gets a message so an unshield looks like any other tx
        const messages: Hex[] = [
            await fakeMessage(nonce(3007)),
            await fakeMessage(nonce(3001)),
            await fakeMessage(nonce(3002)),
            await fakeMessage(nonce(3003)),
        ];
        const { publicHash, firstMessageHash } = publicHashOf(messages);

        const sigHash = hashSpendSignatureInputs({
            publicHash,
            spendCommitmentHashes: [hashNote(bobNote), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

        const now = (await publicClient.getBlock()).timestamp;
        const ts = { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: publicHash,
                first_message_hash: firstMessageHash,
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
                    spendInput(bobNote, bobAsset, localProof, edgeIndex),
                    fakeSpendInput(nonce(3004)),
                    fakeSpendInput(nonce(3005)),
                    fakeSpendInput(nonce(3006)),
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
                noUnshieldCommitment,
                noUnshieldCommitment,
                noUnshieldCommitment,
            ],
            // the long form: what a wallet sends when it can't know whether the wrapper exists on the target chain yet.
            // Here it does, so the factory only reads the first two fields
            unshieldTargets: [{ wrapperFactory, wrapperArgs: encodeWrapperDeployArgs(bobWrapper, deployInfo) }, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages,
            publicHash,
            proof,
        };

        const wrappedBefore = await wrapper.read.balanceOf([bobAddress]);
        await send(warptoad.write.transactPrivate([tx]));
        assert.equal(await wrapper.read.balanceOf([bobAddress]), wrappedBefore + 300n, "bob got his wrapped USDC");
        // the unshield note stayed out of the tree, the 3 fakes went in
        const after = await tree();
        assert.deepEqual(after.leaves.slice(-3), recipientHashes.slice(1));
        assert.equal(after.indexOf(hashNote(unshieldNote)), -1);

        // and out of warptoad entirely
        const underlyingBefore = await token.read.balanceOf([bobAddress]);
        await send(factory.write.unWrap([bobWrapper, 300n, bobAddress], { account: bobWallet.account }));
        assert.equal(await wrapper.read.balanceOf([bobAddress]), wrappedBefore, "wrapped USDC burned");
        assert.equal(await token.read.balanceOf([bobAddress]), underlyingBefore + 300n, "bob has real USDC");
    });

    /** decryptNote always fills in the optional Note fields */
    function recipientDefaults() {
        return { circuitCompSelector: JOIN_SPLIT_SELECTOR, circuitCompStorage: [0n, 0n, 0n] };
    }
});
