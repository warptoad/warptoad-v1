/**
 * The happy path again, but bob no longer "just knows" what alice sent him:
 *
 *   1. alice shields 400 to herself, with a note encrypted to her own view key
 *   2. alice sends bob 300 and 100 change, one encrypted note per slot, fakes get garbage.
 *      A relayer that swaps a message gets VerificationFailed, the messages are in public_hash
 *   3. bob and alice scan every Message event from block 0 and find exactly their own notes
 *
 * Needs `pnpm noir` first, same as ClaudesLilHappyPath
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { Note, WarptoadContract } from "../src/types.js";
import { chainName, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";
import { CIRCUIT_CONTR_STORAGE_EMPTY_HASH, CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR } from "../src/constants.js";
import {
    hashFakeCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashOwner,
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
} from "../src/proving.js";
import { decryptNote, deriveViewKey, encryptNote, fakeMessage, getAllNotes, publicHashOf } from "../src/messages.js";
import { deployCreate2, type Create2Artifact, deployCreate2Factory } from "@warptoad/skinny-fat-imt-js/create2";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { Hex } from "viem";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import skinnyIMTArtifact from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/SkinnyIMTPoseidon2WriteStorage" with { type: "json" };
import IMTSalts from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/create2-salts.json" with { type: "json" };
import poseidon2YulArtifact from "poseidon2-evm/out/Poseidon2Yul.sol/Poseidon2Yul_BN254.json" with { type: "json" };

const POSEIDON2_YUL = "0xB2542195Ad96AcfBC962C48A97D7640A9F5386D2" as const;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudeLilMessaging", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, aliceWallet] = await viem.getWalletClients();

    let warptoad: WarptoadContract;
    let token: ContractReturnType<"MockERC20">;
    let wrapper: ContractReturnType<"WarptoadERC20">;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
    let assetId: bigint;
    const gigaIndex = 0n;

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
    for (const who of [alice, bob]) {
        const [x, y] = derivePublicKey(who.eddsaKey);
        who.pubKey = { x, y };
        who.ownerHash = hashOwner({ spendPubKey: who.pubKey, destGigaIndex: gigaIndex, nullifierSecret: who.nullifierSecret });
    }

    let aliceDeposit: Note;
    let bobNote: Note;
    let aliceChange: Note;

    async function tree() {
        const expectedRoot = await warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(warptoad.address, publicClient, treeId, { expectedRoot });
    }

    before(async () => {
        await deployCreate2Factory(publicClient, deployer, deployer.account);
        const skinnyIMT = await deployCreate2({
            artifact: skinnyIMTArtifact as Create2Artifact,
            salt: IMTSalts.SkinnyIMTPoseidon2WriteStorage[0] as Hex,
            walletClient: deployer,
            publicClient: publicClient,
        });
        const testClient = await viem.getTestClient();
        await testClient.setCode({
            address: POSEIDON2_YUL,
            bytecode: poseidon2YulArtifact.deployedBytecode.object as Hex,
        });
        const verifier = await viem.deployContract("WarptoadVerifier");
        const chainLabels = chainName(await publicClient.getChainId());
        warptoad = await viem.deployContract(
            "Warptoad",
            [SYMBOL_PREFIX, NAME_PREFIX, chainLabels.symbol, chainLabels.name, gigaIndex, verifier.address, BigInt(CIRCUIT_SIZE), 0n, 0n, []],
            { libraries: { SkinnyIMTPoseidon2WriteStorage: skinnyIMT.address } },
        );
        treeId = await warptoad.read.commitmentTreeId();

        token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
        await token.write.mint([aliceWallet.account.address, 1000n]);
        await token.write.approve([warptoad.address, 1000n], { account: aliceWallet.account });

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
        await warptoad.write.wrapERC20([token.address, 1000n, aliceWallet.account.address], { account: aliceWallet.account });
        wrapper = await viem.getContractAt("WarptoadERC20", await warptoad.read.erc20WrapperOf([token.address]));
        assetId = await warptoad.read.hashAssetId([token.address, 0n, gigaIndex, 0]);

        aliceDeposit = { ownerHash: alice.ownerHash, sharedNonce: 1001n, assetId, amount: 400n };
        const preCommitmentHash = hashPreCommitment({
            ownerHash: alice.ownerHash,
            sharedNonce: aliceDeposit.sharedNonce,
            circuitContrSelector: JOIN_SPLIT_SELECTOR,
            circuitContrStorageHash: CIRCUIT_CONTR_STORAGE_EMPTY_HASH,
        });
        const message = await encryptNote(aliceDeposit, alice.view.publicKey);
        await warptoad.write.shieldErc20([wrapper.address, 400n, preCommitmentHash, message], { account: aliceWallet.account });

        assert.deepEqual((await tree()).leaves, [hashNote(aliceDeposit)]);
        assert.deepEqual(await getAllNotes(warptoad, publicClient, alice.view.privateKey), [{ ...aliceDeposit, ...recipientDefaults() }]);
    });

    it("2. alice sends bob 300 and 100 change, messages included, relayer can't touch them", async () => {
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

        // one message per slot, the fakes get one nobody can open
        const messages: Hex[] = [
            await encryptNote(bobNote, bob.view.publicKey),
            await encryptNote(aliceChange, alice.view.publicKey),
            await fakeMessage(2003n),
            await fakeMessage(2004n),
        ];
        const { hash: publicHash, preimage: publicHashPreimage } = publicHashOf(messages);

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
                unshielding_commitments: [noUnshield(), noUnshield(), noUnshield(), noUnshield()],
                nullifiers,
                recipient_commitments_hashes: recipientHashes,
            },
            priv_in: {
                public_hash_preimage: publicHashPreimage,
                recipient_commitments: recipients.map(function (n) {
                    return recipientInput(n);
                }),
                actual_amount_recipient_commitments: 2,
                spend_commitments: [
                    spendInput(aliceDeposit, localProof, edgeIndex),
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
                circuit_contr_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [0, 1, 2, 3].map(function () {
                return { recipient: 0n, amount: 0n, assetId: 0n };
            }),
            unshieldTargets: [0, 1, 2, 3].map(function () {
                return { wrapper: ZERO_ADDRESS, id: 0n };
            }),
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages,
            proof,
        };
        assert.equal(await warptoad.read.hashPublic([messages]), publicHash);

        // a relayer swapping bob's message for garbage changes public_hash, which alice signed.
        // The generated verifier reverts with its own errors instead of returning false, so no VerificationFailed to match on
        const tampered = { ...tx, messages: [await fakeMessage(666n), ...messages.slice(1)] };
        await assert.rejects(warptoad.write.verifyShieldedTx([tampered]));
        assert.deepEqual((await tree()).leaves, [hashNote(aliceDeposit)], "nothing got inserted");

        await warptoad.write.verifyShieldedTx([tx]);
        assert.deepEqual((await tree()).leaves, [hashNote(aliceDeposit), ...recipientHashes]);
    });

    it("3. bob and alice find their notes by scanning from block 0", async () => {
        const bobNotes = await getAllNotes(warptoad, publicClient, bob.view.privateKey);
        assert.deepEqual(bobNotes, [{ ...bobNote, ...recipientDefaults() }]);

        const aliceNotes = await getAllNotes(warptoad, publicClient, alice.view.privateKey);
        assert.deepEqual(aliceNotes, [aliceDeposit, aliceChange].map(function (n) {
            return { ...n, ...recipientDefaults() };
        }));

        // and what bob found is really a leaf he can spend from
        const localTree = await tree();
        assert.notEqual(localTree.indexOf(hashNote(bobNotes[0])), -1);
    });

    /** decryptNote always fills in the optional Note fields */
    function recipientDefaults() {
        return { circuitContrSelector: JOIN_SPLIT_SELECTOR, circuitContrStorage: [0n, 0n, 0n] };
    }
});
