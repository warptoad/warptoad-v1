/**
 * The two ways a swaptoad lock ends, all on one chain:
 *
 *   1. alice shields 400 USDC into two swaptoad locks, bob shields 500 DAI as a normal note
 *   2. alice cancels the first lock: no order signature, the 400 come back to her as a plain note
 *   3. alice signs an order on the second lock (300 USDC for 200 DAI) and bob fills it: 4 new notes,
 *      bob builds alice's two from the lock's shared secret
 *   4. alice unshields the 200 DAI bob made for her and unwraps it, bob does the same with his 300 USDC
 *
 * A lock is a note with circuit_comp_selector = SWAP_TOAD_SELECTOR and, in circuit_comp_storage, the pubkey that
 * signs orders on it plus a shared nullifier secret. The lock is nullified with that secret, not the owner's, so
 * whoever gets the secret with the order can spend the lock, but only the way the order says.
 *
 * Same setup as ClaudesLilHappyPath: no encrypted blobs, secrets just pasted around. Needs `pnpm noir` first
 *
 * Also runs against a real deployment, same as ClaudeLilMessaging (see README, Deploy):
 *   pnpm hardhat run test/ClaudesLilSwapToad.test.ts --network sepolia
 * Warptoad and the factory come from ignition/deployments/chain-<id>/, alice and bob are the second and third
 * configured accounts (the deployer tops them up with gas), and nonces and lock secrets are randomised so reruns
 * don't collide
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { Asset, Note, WarptoadContract, WrapperERC20Contract, WrapperFactoryContract } from "../src/types.js";
import { JOIN_SPLIT_SELECTOR, SWAP_TOAD_SELECTOR } from "../src/constants.js";
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
    unshieldInput,
} from "../src/proving.js";
import { assetOf, encodeWrapperArgs } from "../src/assets.js";
import { publicHashOf } from "../src/messages.js";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { parseUnits, type Address, type Hex } from "viem";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { deployInfra, deployWarptoad, fundIfLow, wrap, ZERO_ADDRESS, type WalletClient } from "./fixtures.js";

/** amounts in the token's own decimals: USDC has 6, DAI 18. Notes and the circuit only ever see the raw integer */
const USDC = (amount: string) => parseUnits(amount, 6);
const DAI = (amount: string) => parseUnits(amount, 18);

const NO_MESSAGES: Hex[] = ["0x", "0x", "0x", "0x"];
const { publicHash: PUBLIC_HASH, firstMessageHash: FIRST_MESSAGE_HASH } = publicHashOf(NO_MESSAGES);
const noTarget = { wrapperFactory: ZERO_ADDRESS, wrapperArgs: "0x" as Hex };
const noUnshieldCommitment = { recipient: 0n, amount: 0n, assetId: 0n };
/** MockERC20s to reuse on a live chain, anyone can mint them. A missing one gets deployed and its address printed */
const MOCK_TOKENS: Record<number, { USDC?: Address; DAI?: Address }> = {
    11155111: { USDC: "0x5afC539F572A1C4CF4c7FcC4ef3169c232F9c0E4" },
};
const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

describe("ClaudesLilSwapToad", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    // the live network config has three keys, see hardhat.config.ts. A config with fewer falls back to the deployer
    const [deployer, aliceWallet = deployer, bobWallet = deployer] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();
    const live = chainId !== 31337;
    // fake nullifiers, fake commitments and lock secrets are hashed into leaves and nullifiers, so every live run needs fresh ones
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

    let warptoad: WarptoadContract;
    let factory: WrapperFactoryContract;
    let usdc: ContractReturnType<"MockERC20">;
    let dai: ContractReturnType<"MockERC20">;
    let usdcWrapper: WrapperERC20Contract;
    let daiWrapper: WrapperERC20Contract;
    let bb: Barretenberg;
    let backend: UltraHonkBackend;
    let treeId: bigint;
    let gigaIndex: bigint;
    let usdcAsset: Asset;
    let usdcId: bigint;
    let daiAsset: Asset;
    let daiId: bigint;

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

    // one shared secret per lock: it nullifies the lock and seeds the nonces of the maker's notes on a fill
    const cancelLockSecret = nonce(0x5ec1);
    const fillLockSecret = nonce(0x5ec2);
    function lockStorage(sharedNullifierSecret: bigint): CircuitCompStorage {
        return [alice.orderPubKey.x, alice.orderPubKey.y, sharedNullifierSecret];
    }

    let cancelLock: Note;
    let fillLock: Note;
    let bobDai: Note;
    // what the fill leaves them with, unshielded in step 4
    let alicePayment: Note;
    let bobUsdc: Note;

    async function tree() {
        const expectedRoot = await warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(warptoad.address, publicClient, treeId, { expectedRoot });
    }

    async function timeStamps() {
        const now = (await publicClient.getBlock()).timestamp;
        return { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
    }

    async function mockToken(symbol: "USDC" | "DAI", name: string, decimals: number, holder: Address, amount: bigint) {
        const known = MOCK_TOKENS[chainId]?.[symbol];
        let token: ContractReturnType<"MockERC20">;
        if (known !== undefined) {
            token = await viem.getContractAt("MockERC20", known);
        } else {
            token = await viem.deployContract("MockERC20", [name, symbol, decimals]);
            if (live) console.log(`deployed MockERC20 ${symbol} at ${token.address}, add it to MOCK_TOKENS to reuse it`);
        }
        assert.equal(await token.read.decimals(), decimals, `${symbol} mock has the decimals the amounts assume`);
        await send(token.write.mint([holder, amount]));
        await send(token.write.approve([factory.address, amount], { account: holder }));
        return token;
    }

    before(async () => {
        if (live) {
            const deployed = JSON.parse(await readFile(`ignition/deployments/chain-${chainId}/deployed_addresses.json`, "utf8"));
            warptoad = await viem.getContractAt("Warptoad", deployed["Warptoad#Warptoad"]);
            factory = await viem.getContractAt("WrapperFactory", deployed["Warptoad#WrapperFactory"]);
        } else {
            ({ warptoad, factory } = await deployWarptoad(viem, await deployInfra(viem, publicClient, deployer)));
        }
        treeId = await warptoad.read.commitmentTreeId();
        // owner hashes are bound to the chain they can be spent on, so they wait for the contract's giga index
        gigaIndex = BigInt(await warptoad.read.gigaIndex());
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

        if (live) {
            await fundIfLow(publicClient, deployer, aliceWallet.account.address);
            await fundIfLow(publicClient, deployer, bobWallet.account.address);
        }
        usdc = await mockToken("USDC", "USD Coin", 6, aliceWallet.account.address, USDC("1000"));
        dai = await mockToken("DAI", "Dai Stablecoin", 18, bobWallet.account.address, DAI("1000"));

        bb = await Barretenberg.new({ threads: cpus().length });
        backend = new UltraHonkBackend(circuit.bytecode, bb);
    });

    after(async () => {
        await bb.destroy();
    });

    it("1. alice locks 400 USDC twice, bob shields 500 DAI", async () => {
        usdcWrapper = await wrap(viem, { factory, gigaIndex }, usdc.address, USDC("1000"), aliceWallet.account.address, aliceWallet.account.address);
        daiWrapper = await wrap(viem, { factory, gigaIndex }, dai.address, DAI("1000"), bobWallet.account.address, bobWallet.account.address);
        const [firstGigaIndex, lastGigaIndex] = await factory.read.gigaIndexRange();
        usdcAsset = assetOf({ wrapperFactory: factory.address, wrapper: usdcWrapper.address, underlying: usdc.address, firstGigaIndex, lastGigaIndex });
        daiAsset = assetOf({ wrapperFactory: factory.address, wrapper: daiWrapper.address, underlying: dai.address, firstGigaIndex, lastGigaIndex });
        usdcId = hashAssetId(usdcAsset);
        daiId = hashAssetId(daiAsset);

        cancelLock = {
            ownerHash: alice.ownerHash,
            sharedNonce: nonce(1001),
            assetId: usdcId,
            amount: USDC("400"),
            circuitCompSelector: SWAP_TOAD_SELECTOR,
            circuitCompStorage: lockStorage(cancelLockSecret),
        };
        fillLock = { ...cancelLock, sharedNonce: nonce(1002), circuitCompStorage: lockStorage(fillLockSecret) };
        bobDai = { ownerHash: bob.ownerHash, sharedNonce: nonce(1003), assetId: daiId, amount: DAI("500") };

        // shield takes any pre_commitment_hash, so a lock can be made straight from a wrapper balance
        const aliceUsdcBefore = await usdcWrapper.read.balanceOf([aliceWallet.account.address]);
        const bobDaiBefore = await daiWrapper.read.balanceOf([bobWallet.account.address]);
        const usdcArgs = encodeWrapperArgs({ wrapper: usdcWrapper.address, underlying: usdc.address });
        for (const lock of [cancelLock, fillLock]) {
            await send(warptoad.write.shield([factory.address, preCommitmentHashOf(lock), lock.amount, usdcArgs, "0x"], { account: aliceWallet.account }));
        }
        const daiArgs = encodeWrapperArgs({ wrapper: daiWrapper.address, underlying: dai.address });
        await send(warptoad.write.shield([factory.address, preCommitmentHashOf(bobDai), bobDai.amount, daiArgs, "0x"], { account: bobWallet.account }));

        assert.equal(await usdcWrapper.read.balanceOf([aliceWallet.account.address]), aliceUsdcBefore - USDC("800"));
        assert.equal(await daiWrapper.read.balanceOf([bobWallet.account.address]), bobDaiBefore - DAI("500"));
        assert.deepEqual((await tree()).leaves.slice(-3), [cancelLock, fillLock, bobDai].map(hashNote));
    });

    it("2. alice cancels a lock without an order signature, the 400 come back as a plain note", async () => {
        const localTree = await tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(cancelLock));

        // the only real new note: same asset and amount as the lock, the circuit checks nothing else about it
        const refund: Note = { ownerHash: alice.ownerHash, sharedNonce: nonce(2001), assetId: usdcId, amount: cancelLock.amount };
        const recipients = [refund, fakeNote(nonce(2002)), fakeNote(nonce(2003)), fakeNote(nonce(2004))];
        const recipientHashes = [
            hashNote(refund),
            hashFakeCommitment({ nonce: nonce(2002) }),
            hashFakeCommitment({ nonce: nonce(2003) }),
            hashFakeCommitment({ nonce: nonce(2004) }),
        ] as CircuitSizeFields;
        // the lock is nullified with its shared secret, not alice's own, so a cancel and a fill spend the same nullifier
        const nullifiers = [
            hashNullifier({ nullifierSecret: cancelLockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashFakeNullifier({ nonce: nonce(2005) }),
            hashFakeNullifier({ nonce: nonce(2006) }),
            hashFakeNullifier({ nonce: nonce(2007) }),
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
        await send(warptoad.write.transactPrivate([tx]));

        assert.equal(await warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.deepEqual((await tree()).leaves.slice(-4), recipientHashes);
    });

    it("3. bob fills alice's order: 300 of the locked USDC for 200 DAI", async () => {
        const localTree = await tree();
        const { proof: lockProof, edgeIndex } = merkleProofInput(localTree, hashNote(fillLock));
        const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai));
        const ts = await timeStamps();

        // ---- alice's side, all of it before bob shows up: the order, and the two notes bob will make for her.
        // She sells 300 of the 400 locked USDC for 200 DAI, so 1.5 USDC per DAI. Amounts are raw integers in each
        // token's own decimals, the circuit never compares across assets so the different decimals don't matter to it
        const listingAmount = USDC("300");
        const paymentAmount = DAI("200");
        // their nonces come from the lock's secret so bob can't pick them, type 0 is the payment, 1 the change
        alicePayment = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: fillLockSecret, commitmentType: 0n }),
            assetId: daiId,
            amount: paymentAmount,
        };
        const aliceChange: Note = {
            ownerHash: alice.ownerHash,
            sharedNonce: hashSharedNonceSwaptoad({ sharedNullifierSecret: fillLockSecret, commitmentType: 1n }),
            assetId: usdcId,
            amount: fillLock.amount - listingAmount,
        };
        // `SwapToadOrder` in circuits/src/main.nr, in the order the maker signs it. The order must outlive the proof.
        // first_message_hash pins messages[0] and [1], where the notes for aliceChange and alicePayment would go.
        // The owner keys hash is what lets the circuit check the lock is on this chain's giga index
        const order = authSigInputs([
            usdcId,
            listingAmount,
            daiId,
            paymentAmount,
            ts.proof_expire_time_stamp + 3600n,
            FIRST_MESSAGE_HASH,
            preCommitmentHashOf(aliceChange),
            alice.ownerKeysHash,
        ]);
        const orderSig = signMessage(alice.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));

        // ---- bob's side: alice handed him the order, its signature and fillLockSecret
        const bobChange: Note = { ownerHash: bob.ownerHash, sharedNonce: nonce(3001), assetId: daiId, amount: bobDai.amount - paymentAmount };
        bobUsdc = { ownerHash: bob.ownerHash, sharedNonce: nonce(3002), assetId: usdcId, amount: listingAmount };
        // slot order is fixed by the circuit: maker change, maker payment, taker change, taker payment
        const recipients = [aliceChange, alicePayment, bobChange, bobUsdc];
        const recipientHashes = recipients.map(hashNote) as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: fillLockSecret, gigaLeafIndex: gigaIndex, localLeafIndex: lockProof.index }),
            hashNullifier({ nullifierSecret: bob.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
            hashFakeNullifier({ nonce: nonce(3003) }),
            hashFakeNullifier({ nonce: nonce(3004) }),
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
                    fakeSpendInput(nonce(3003)),
                    fakeSpendInput(nonce(3004)),
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
        await send(warptoad.write.transactPrivate([tx]));

        assert.equal(await warptoad.read.nullifiers([nullifiers[0]]) > 0n, true, "the lock is spent");
        assert.equal(await warptoad.read.nullifiers([nullifiers[1]]) > 0n, true, "bob's DAI note is spent");
        assert.deepEqual((await tree()).leaves.slice(-4), recipientHashes);
        // the lock can't be filled twice
        await assert.rejects(warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
    });

    /**
     * a plain join_split unshield of `note` to `wallet`'s address, relayed by the deployer, then `wallet` unwraps
     * it on the factory. Same shape as step 3 of ClaudesLilHappyPath. `n` is the nonce base for this tx's fakes
     */
    async function unshieldAndUnwrap(
        note: Note,
        asset: Asset,
        owner: { eddsaKey: string; nullifierSecret: bigint; pubKey: { x: bigint; y: bigint } },
        wallet: WalletClient,
        wrapper: WrapperERC20Contract,
        token: ContractReturnType<"MockERC20">,
        n: number,
    ) {
        const localTree = await tree();
        const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(note));
        const recipient = wallet.account.address;

        // an unshield is a recipient note whose owner hash is the eth address, unshields have to come first
        const unshieldNote: Note = { ownerHash: BigInt(recipient), sharedNonce: 0n, assetId: note.assetId, amount: note.amount };
        const recipients = [unshieldNote, fakeNote(nonce(n + 1)), fakeNote(nonce(n + 2)), fakeNote(nonce(n + 3))];
        const recipientHashes = [
            hashNote(unshieldNote),
            hashFakeCommitment({ nonce: nonce(n + 1) }),
            hashFakeCommitment({ nonce: nonce(n + 2) }),
            hashFakeCommitment({ nonce: nonce(n + 3) }),
        ] as CircuitSizeFields;
        const nullifiers = [
            hashNullifier({ nullifierSecret: owner.nullifierSecret, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
            hashFakeNullifier({ nonce: nonce(n + 4) }),
            hashFakeNullifier({ nonce: nonce(n + 5) }),
            hashFakeNullifier({ nonce: nonce(n + 6) }),
        ] as CircuitSizeFields;
        const sigHash = hashSpendSignatureInputs({
            publicHash: PUBLIC_HASH,
            spendCommitmentHashes: [hashNote(note), 0n, 0n, 0n],
            recipientCommitmentHashes: recipientHashes,
        });
        const sig = signMessage(owner.eddsaKey, sigHash);

        const ts = await timeStamps();
        const { proof } = await prove(backend, circuit as CompiledCircuit, {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: PUBLIC_HASH,
                first_message_hash: FIRST_MESSAGE_HASH,
                unshielding_commitments: [unshieldInput(recipient, note.assetId, note.amount), noUnshield(), noUnshield(), noUnshield()],
                nullifiers,
                recipient_commitments_hashes: recipientHashes,
            },
            priv_in: {
                recipient_commitments: recipients.map(function (r) {
                    return recipientInput(r);
                }),
                actual_amount_recipient_commitments: 1,
                spend_commitments: [
                    spendInput(note, asset, localProof, edgeIndex),
                    fakeSpendInput(nonce(n + 4)),
                    fakeSpendInput(nonce(n + 5)),
                    fakeSpendInput(nonce(n + 6)),
                ],
                actual_amount_spend_commitments: 1,
                owner: {
                    pub_key: owner.pubKey,
                    nullifier_secret: owner.nullifierSecret,
                    signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
                },
                auth: noAuth(),
                circuit_comp_selector: JOIN_SPLIT_SELECTOR,
            },
        });

        const underlying = await wrapper.read.underlying();
        const tx = {
            roots: { localRoot: localTree.root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
            unshieldingCommitments: [{ recipient: BigInt(recipient), amount: note.amount, assetId: note.assetId }, noUnshieldCommitment, noUnshieldCommitment, noUnshieldCommitment],
            unshieldTargets: [{ wrapperFactory: factory.address, wrapperArgs: encodeWrapperArgs({ wrapper: wrapper.address, underlying }) }, noTarget, noTarget, noTarget],
            nullifiers: [...nullifiers],
            recipientCommitmentsHashes: [...recipientHashes],
            messages: NO_MESSAGES,
            publicHash: PUBLIC_HASH,
            proof,
        };

        const wrappedBefore = await wrapper.read.balanceOf([recipient]);
        const underlyingBefore = await token.read.balanceOf([recipient]);
        await send(warptoad.write.transactPrivate([tx]));
        assert.equal(await wrapper.read.balanceOf([recipient]), wrappedBefore + note.amount, "unshielded into the wrapper");
        assert.equal(await warptoad.read.nullifiers([nullifiers[0]]) > 0n, true);

        await send(factory.write.unWrap([wrapper.address, note.amount, recipient], { account: wallet.account }));
        assert.equal(await wrapper.read.balanceOf([recipient]), wrappedBefore, "wrapper burned");
        assert.equal(await token.read.balanceOf([recipient]), underlyingBefore + note.amount, "got the underlying");
    }

    it("4. alice unshields and unwraps the 200 DAI bob made for her, bob his 300 USDC", async () => {
        // the maker's note was built by the taker, so this is the proof it came out spendable
        await unshieldAndUnwrap(alicePayment, daiAsset, alice, aliceWallet, daiWrapper, dai, 4000);
        await unshieldAndUnwrap(bobUsdc, usdcAsset, bob, bobWallet, usdcWrapper, usdc, 5000);
    });
});
