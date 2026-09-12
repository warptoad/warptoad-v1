/**
 * The simplest possible end to end run of the main circuit, all on one chain:
 *
 *   1. alice wraps USDC and shields 400 of it
 *   2. alice sends bob 300 shielded, keeps 100 as change
 *   3. bob unshields his 300 back into wrapped USDC
 *
 * Witness with noir_js, proof with bb.js, tree synced with skinny-fat-imt-js, secrets just pasted
 * around. No utxo management, no encrypted blobs, bob "just knows" what alice sent him.
 *
 * Needs `pnpm noir` first: the circuit json comes from circuits/target and the verifier from contracts/.
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
    unshieldInput,
} from "../src/proving.js";
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
// the esm build of eddsa-poseidon trips over blakejs' cjs exports under node, the cjs build is fine
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudesLilHappyPath", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, aliceWallet, bobWallet] = await viem.getWalletClients();

    let warptoad: WarptoadContract;
    let token: ContractReturnType<"MockERC20">;
    let wrapper: ContractReturnType<"WarptoadERC20">;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
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
        who.ownerHash = hashOwner({ spendPubKey: who.pubKey, destGigaIndex: gigaIndex, nullifierSecret: who.nullifierSecret });
    }

    // the notes that exist during the story
    let aliceDeposit: Note;
    let bobNote: Note;
    let aliceChange: Note;

    async function tree() {
        const expectedRoot = await warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(warptoad.address, publicClient, treeId, { expectedRoot });
    }

    async function timeStamps() {
        const now = (await publicClient.getBlock()).timestamp;
        return { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
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

    it("1. alice wraps and shields 400", async () => {
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
        await warptoad.write.shieldErc20([wrapper.address, 400n, preCommitmentHash], { account: aliceWallet.account });

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
            publicHash: 0n,
            spendCommitmentHashes: [hashNote(aliceDeposit), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(alice.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof, publicInputs } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: 0n,
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
            proof,
        };
        // the contract lays public inputs out the same way bb did
        const formatted = await warptoad.read.formatPublicInputs([
            tx.roots, tx.timeStamps, 0n, tx.unshieldingCommitments, tx.nullifiers, tx.recipientCommitmentsHashes,
        ]);
        assert.deepEqual(
            formatted.map(function (x) {
                return BigInt(x);
            }),
            publicInputs,
        );

        // anyone can relay it, deployer does here
        await warptoad.write.verifyShieldedTx([tx]);

        assert.equal(await warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "alice's deposit is spent");
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
            publicHash: 0n,
            spendCommitmentHashes: [hashNote(bobNote), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(bob.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: 0n,
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
                    spendInput(bobNote, localProof, edgeIndex),
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
                circuit_contr_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const noTarget = { wrapper: ZERO_ADDRESS, id: 0n };
        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [
                { recipient: BigInt(bobAddress), amount: 300n, assetId },
                { recipient: 0n, amount: 0n, assetId: 0n },
                { recipient: 0n, amount: 0n, assetId: 0n },
                { recipient: 0n, amount: 0n, assetId: 0n },
            ],
            unshieldTargets: [{ wrapper: wrapper.address, id: 0n }, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            proof,
        };
        await warptoad.write.verifyShieldedTx([tx]);

        assert.equal(await wrapper.read.balanceOf([bobAddress]), 300n, "bob got his wrapped USDC");
        // the unshield note stayed out of the tree, the 3 fakes went in
        const after = await tree();
        assert.equal(after.size, 5 + 3);
        assert.equal(after.indexOf(hashNote(unshieldNote)), -1);

        // and bob can't do it twice
        await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /NullifierAlreadySpent/);
    });
});
