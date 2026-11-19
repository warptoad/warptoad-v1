/**
 * Shared setup for the swaptoad tests, ClaudesLilSwapToadFill and ClaudesLilSwapToadCancel. Not a test file,
 * node:test just finds nothing in here, same as fixtures.ts.
 *
 * `connectSwapToad` gives a test the chain, the contracts, alice and bob and a prover. `setupToken` mints a mock,
 * wraps it for one of them and resolves the asset. The other helpers are the tx shapes both flows share: shielding a
 * note, the `ShieldedTx` struct, and a plain join_split unshield followed by an unwrap.
 *
 * Runs on hardhat and on a live chain (see README, Deploy). Live: Warptoad and the factory come from
 * ignition/deployments/chain-<id>/, alice and bob are the second and third configured accounts (the deployer tops
 * them up with gas), and nonces are randomised so reruns don't collide
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { parseUnits, type Address, type Hex } from "viem";
import type { derivePublicKey as DerivePublicKey, signMessage as SignMessage } from "@zk-kit/eddsa-poseidon";
import type { Asset, Note, TimeStampsInput, WarptoadContract, WrapperERC20Contract, WrapperFactoryContract } from "../src/types.js";
import { CIRCUIT_COMP_STORAGE_SIZE, SWAP_TOAD_ORDER_SIZE, SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashAssetId,
    hashFakeCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashOwner,
    hashOwnerKeys,
    hashPublic,
    type CircuitCompAuthSigInputs,
    type CircuitCompStorage,
    type CircuitSizeFields,
    type PubKey,
} from "../src/hashing.js";
import {
    authSigInputs,
    fakeNote,
    fakeSpendInput,
    hashNote,
    joinSplitSelectors,
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
    zeros,
} from "../src/proving.js";
import { assetOf, encodeWrapperArgs } from "../src/assets.js";
import { hashMessages } from "../src/messages.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import { deployInfra, deployWarptoad, fundIfLow, wrap, ZERO_ADDRESS, type WalletClient } from "./fixtures.js";

/** amounts in the token's own decimals: USDC has 6, DAI 18. Notes and the circuit only ever see the raw integer */
export const USDC = (amount: string) => parseUnits(amount, 6);
export const DAI = (amount: string) => parseUnits(amount, 18);

// no encrypted blobs in these tests, but the contract always hashes every message into message_hashes. A maker's
// order names the ones for its new notes, and all of them go into public_hash, which the spender signs.
// See ClaudeLilMessaging.test.ts
export const NO_MESSAGES: Hex[] = ["0x", "0x", "0x", "0x"];
export const MESSAGE_HASHES = hashMessages(NO_MESSAGES);
const noTarget = { wrapperFactory: ZERO_ADDRESS, wrapperArgs: "0x" as Hex };
const noUnshieldCommitment = { recipient: 0n, amount: 0n, assetId: 0n };
/** MockERC20s to reuse on a live chain, anyone can mint them. A missing one gets deployed and its address printed */
const MOCK_TOKENS: Record<number, { USDC?: Address; DAI?: Address }> = {
    11155111: { USDC: "0x5afC539F572A1C4CF4c7FcC4ef3169c232F9c0E4" },
};
// the esm build of eddsa-poseidon trips over blakejs' cjs exports under node, the cjs build is fine
export const { derivePublicKey, signMessage } = createRequire(import.meta.url)("@zk-kit/eddsa-poseidon") as {
    derivePublicKey: typeof DerivePublicKey;
    signMessage: typeof SignMessage;
};

/** someone with shielded funds: their eddsa spending key, nullifier secret and the eth account they wrap and unwrap with */
export type Party = {
    eddsaKey: string;
    nullifierSecret: bigint;
    pubKey: PubKey;
    ownerKeysHash: bigint;
    ownerHash: bigint;
    wallet: WalletClient;
};
/** a swaptoad note, the keys it sits under and the eddsa key that signs orders on it, see `swapToadNote` */
export type SwapToadNote = { note: Note; owner: Party; orderKey: string };

/** a mock token, its wrapper, and the asset notes of it carry */
export type TokenSide = {
    token: ContractReturnType<"MockERC20">;
    wrapper: WrapperERC20Contract;
    asset: Asset;
    id: bigint;
    /** `wrapperArgs` for shield and unshield */
    args: Hex;
};

export type SwapToadWorld = Awaited<ReturnType<typeof connectSwapToad>>;

export async function connectSwapToad() {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    // the live network config has three keys, see hardhat.config.ts. A config with fewer falls back to the deployer
    const [deployer, aliceWallet = deployer, bobWallet = deployer] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();
    const live = chainId !== 31337;
    // fake nullifiers, fake commitments and per note secrets are hashed into leaves and nullifiers, so every live run needs fresh ones
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
    if (live) {
        const deployed = JSON.parse(await readFile(`ignition/deployments/chain-${chainId}/deployed_addresses.json`, "utf8"));
        warptoad = await viem.getContractAt("Warptoad", deployed["Warptoad#Warptoad"]);
        factory = await viem.getContractAt("WrapperFactory", deployed["Warptoad#WrapperFactory"]);
        await fundIfLow(publicClient, deployer, aliceWallet.account.address);
        await fundIfLow(publicClient, deployer, bobWallet.account.address);
    } else {
        ({ warptoad, factory } = await deployWarptoad(viem, await deployInfra(viem, publicClient, deployer)));
    }
    const treeId = await warptoad.read.commitmentTreeId();
    // owner hashes are bound to the chain they can be spent on, so they come from the contract's giga index
    const gigaIndex = BigInt(await warptoad.read.gigaIndex());

    function party(eddsaKey: string, nullifierSecret: bigint, wallet: WalletClient): Party {
        const [x, y] = derivePublicKey(eddsaKey);
        const pubKey = { x, y };
        const ownerKeysHash = hashOwnerKeys({ spendPubKey: pubKey, nullifierSecret });
        return { eddsaKey, nullifierSecret, pubKey, ownerKeysHash, ownerHash: hashOwner({ ownerKeysHash, gigaIndex }), wallet };
    }
    const alice = party("alice's eddsa key, any bytes work", 0xa11cen, aliceWallet);
    const bob = party("bob's eddsa key", 0xb0bn, bobWallet);

    const bb = await Barretenberg.new({ threads: cpus().length });
    const backend = new UltraHonkBackend(circuit.bytecode, bb);

    async function tree() {
        const expectedRoot = await warptoad.read.getSkinnyRoot([treeId]);
        return syncedTree(warptoad.address, publicClient, treeId, { expectedRoot });
    }

    async function timeStamps(): Promise<TimeStampsInput> {
        const now = (await publicClient.getBlock()).timestamp;
        return { proof_expire_time_stamp: now + 3600n, historic_time_stamp: now - 3600n };
    }

    return {
        viem,
        publicClient,
        deployer,
        chainId,
        live,
        nonce,
        send,
        warptoad,
        factory,
        gigaIndex,
        party,
        alice,
        bob,
        backend,
        tree,
        timeStamps,
        async close() {
            await bb.destroy();
        },
    };
}

/** a mock token, minted to and wrapped by `holder`, with the asset its notes carry */
export async function setupToken(
    w: SwapToadWorld,
    symbol: "USDC" | "DAI",
    name: string,
    decimals: number,
    holder: Party,
    amount: bigint,
): Promise<TokenSide> {
    const known = MOCK_TOKENS[w.chainId]?.[symbol];
    let token: ContractReturnType<"MockERC20">;
    if (known !== undefined) {
        token = await w.viem.getContractAt("MockERC20", known);
    } else {
        token = await w.viem.deployContract("MockERC20", [name, symbol, decimals]);
        if (w.live) console.log(`deployed MockERC20 ${symbol} at ${token.address}, add it to MOCK_TOKENS to reuse it`);
    }
    assert.equal(await token.read.decimals(), decimals, `${symbol} mock has the decimals the amounts assume`);
    const holderAddress = holder.wallet.account.address;
    await w.send(token.write.mint([holderAddress, amount]));
    await w.send(token.write.approve([w.factory.address, amount], { account: holder.wallet.account }));
    const wrapper = await wrap(w.viem, w, token.address, amount, holderAddress, holderAddress);

    const [firstGigaIndex, lastGigaIndex] = await w.factory.read.gigaIndexRange();
    const asset = assetOf({ wrapperFactory: w.factory.address, wrapper: wrapper.address, underlying: token.address, firstGigaIndex, lastGigaIndex });
    return { token, wrapper, asset, id: hashAssetId(asset), args: encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address }) };
}

/**
 * the circuit_comp_storage of a swaptoad note, see `SWAPTOAD_STORAGE_OFFSETS` in circuits/src/main.nr: the pubkey its
 * orders are signed with, until when that key may be used, and the secret the note is nullified with. That secret is
 * the note's own and not the owner's, so a taker can be given it. The owner can still spend the note with join_split
 * any time, with the same nullifier, and that is the cancel
 */
export function swapToadStorage(orderPubKey: PubKey, { authExpiry, sharedNullifierSecret }: { authExpiry: bigint; sharedNullifierSecret: bigint }): CircuitCompStorage {
    return [orderPubKey.x, orderPubKey.y, authExpiry, sharedNullifierSecret, ...zeros(CIRCUIT_COMP_STORAGE_SIZE - 4)];
}

/**
 * a swaptoad note of `holder`'s, ready to sign orders on, with the keys it sits under. Shielding or receiving funds
 * straight into one saves the tx that turns a join_split note into a swaptoad note, and its owner still spends it
 * with a plain join_split whenever they want.
 *
 * A taker filling an order on the note gets to see three things of the holder's: the owner keys hash, the pubkey
 * orders are signed with and the note's nullifier secret. So none of them is used twice, or two takers could tell
 * their notes came from the same person: every note gets an owner of its own (the holder's spend key with a fresh
 * nullifier secret, which makes the owner keys hash a new one), an order key of its own and its own nullifier secret.
 * `n` is the nonce base, it uses `n` to `n + 3`
 */
export function swapToadNote(
    w: SwapToadWorld,
    holder: Party,
    { assetId, amount, authExpiry }: { assetId: bigint; amount: bigint; authExpiry: bigint },
    n: number,
): SwapToadNote {
    const owner = w.party(holder.eddsaKey, w.nonce(n + 1), holder.wallet);
    // any bytes work as an eddsa key, a wallet would derive these from a root secret
    const orderKey = `${holder.eddsaKey}, order key ${w.nonce(n + 3)}`;
    const [x, y] = derivePublicKey(orderKey);
    const note: Note = {
        ownerHash: owner.ownerHash,
        sharedNonce: w.nonce(n),
        assetId,
        amount,
        circuitCompSelector: SWAP_TOAD_SELECTOR,
        circuitCompStorage: swapToadStorage({ x, y }, { authExpiry, sharedNullifierSecret: w.nonce(n + 2) }),
    };
    return { note, owner, orderKey };
}

/** the secret `note` is nullified with: its own for a swaptoad note, whoever spends it, and the owner's otherwise */
export function nullifierSecretOf(note: Note, owner: Party): bigint {
    return note.circuitCompSelector === SWAP_TOAD_SELECTOR ? swapToadStorageOf(note).sharedNullifierSecret : owner.nullifierSecret;
}

/** `swapToadStorage` read back, by a taker who was handed the note */
export function swapToadStorageOf(note: Note): { orderPubKey: PubKey; authExpiry: bigint; sharedNullifierSecret: bigint } {
    if (note.circuitCompStorage === undefined) throw new Error("not a swaptoad note, it has no circuit_comp_storage");
    const [x, y, authExpiry, sharedNullifierSecret] = note.circuitCompStorage;
    return { orderPubKey: { x, y }, authExpiry, sharedNullifierSecret };
}

/**
 * what a maker signs, see `SWAPTOAD_ORDER_OFFSETS` in circuits/src/main.nr: the swaptoad selector, the hashes of the
 * notes they want made, of their notes that pay for them, a message hash per new note, and when the order expires.
 * Entry i of each list is slot i of the fill, a shorter list is padded with 0, which the circuit reads as "nothing of
 * the maker's in this slot"
 */
export function swapToadOrder({ newCommitHashes, spendCommitHashes, messageHashes, expiry }: {
    newCommitHashes: bigint[];
    spendCommitHashes: bigint[];
    messageHashes: bigint[];
    expiry: bigint;
}): CircuitCompAuthSigInputs {
    function pad(hashes: bigint[]) {
        if (hashes.length > SWAP_TOAD_ORDER_SIZE) throw new Error(`${hashes.length} hashes, an order takes ${SWAP_TOAD_ORDER_SIZE}`);
        return [...hashes, ...zeros(SWAP_TOAD_ORDER_SIZE - hashes.length)];
    }
    return authSigInputs([SWAP_TOAD_SELECTOR, ...pad(newCommitHashes), ...pad(spendCommitHashes), ...pad(messageHashes), expiry]);
}

/** `Warptoad.shield` from `wallet`'s wrapper balance. shield takes any pre_commitment_hash */
export async function shieldNote(w: SwapToadWorld, side: TokenSide, note: Note, wallet: WalletClient) {
    await w.send(w.warptoad.write.shield([w.factory.address, preCommitmentHashOf(note), note.amount, side.args, "0x"], { account: wallet.account }));
}

/** the `ShieldedTx` struct for `transactPrivate`, with no messages and at most one unshield, in slot 0 */
export function privateTx(
    w: SwapToadWorld,
    { root, edgeIndex, ts, nullifiers, recipientHashes, proof, unshield }: {
        root: bigint;
        edgeIndex: bigint;
        ts: TimeStampsInput;
        nullifiers: CircuitSizeFields;
        recipientHashes: CircuitSizeFields;
        proof: Hex;
        unshield?: { recipient: Address; note: Note; side: TokenSide };
    },
) {
    return {
        roots: { localRoot: root, localEdgeIndex: edgeIndex, gigaRoot: 0n, gigaEdgeIndex: 0n },
        timeStamps: { proofExpireTimeStamp: ts.proof_expire_time_stamp, historicTimeStamp: ts.historic_time_stamp },
        unshieldingCommitments: [
            unshield ? { recipient: BigInt(unshield.recipient), amount: unshield.note.amount, assetId: unshield.note.assetId } : noUnshieldCommitment,
            noUnshieldCommitment,
            noUnshieldCommitment,
            noUnshieldCommitment,
        ],
        unshieldTargets: [unshield ? { wrapperFactory: w.factory.address, wrapperArgs: unshield.side.args } : noTarget, noTarget, noTarget, noTarget],
        nullifiers: [...nullifiers],
        recipientCommitmentsHashes: [...recipientHashes],
        messages: NO_MESSAGES,
        proof,
    };
}

/**
 * a plain join_split unshield of `note` to `owner`'s address, relayed by the deployer, then `owner` unwraps it on
 * the factory. Same shape as step 3 of ClaudesLilHappyPath, and it works on a swaptoad note just the same.
 * `n` is the nonce base for this tx's fakes
 */
export async function unshieldAndUnwrap(w: SwapToadWorld, side: TokenSide, note: Note, owner: Party, n: number) {
    const localTree = await w.tree();
    const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(note));
    const recipient = owner.wallet.account.address;

    // an unshield is a recipient note whose owner hash is the eth address, unshields have to come first
    const unshieldNote: Note = { ownerHash: BigInt(recipient), sharedNonce: 0n, assetId: note.assetId, amount: note.amount };
    const recipients = [unshieldNote, fakeNote(w.nonce(n + 1)), fakeNote(w.nonce(n + 2)), fakeNote(w.nonce(n + 3))];
    const recipientHashes = [
        hashNote(unshieldNote),
        hashFakeCommitment({ nonce: w.nonce(n + 1) }),
        hashFakeCommitment({ nonce: w.nonce(n + 2) }),
        hashFakeCommitment({ nonce: w.nonce(n + 3) }),
    ] as CircuitSizeFields;
    const nullifiers = [
        hashNullifier({ nullifierSecret: nullifierSecretOf(note, owner), sharedNonce: note.sharedNonce, gigaLeafIndex: w.gigaIndex, localLeafIndex: localProof.index }),
        hashFakeNullifier({ nonce: w.nonce(n + 4) }),
        hashFakeNullifier({ nonce: w.nonce(n + 5) }),
        hashFakeNullifier({ nonce: w.nonce(n + 6) }),
    ] as CircuitSizeFields;
    // what the spender authorizes: every message, unshield, nullifier and new note of this tx. The contract
    // computes the same hash, see `hashPublic`
    const unshielding = [unshieldInput(recipient, note.assetId, note.amount), noUnshield(), noUnshield(), noUnshield()];
    const publicHash = hashPublic({ messageHashes: MESSAGE_HASHES, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
    const sig = signMessage(owner.eddsaKey, publicHash);

    const ts = await w.timeStamps();
    const { proof } = await prove(w.backend, circuit as CompiledCircuit, {
        pub_in: {
            roots: pubRoots(localTree.root, edgeIndex, w.gigaIndex),
            time_stamps: ts,
            public_hash: publicHash,
            message_hashes: MESSAGE_HASHES,
            unshielding_commitments: unshielding,
            nullifiers,
            recipient_commitments_hashes: recipientHashes,
        },
        priv_in: {
            recipient_commitments: recipients.map(function (r) {
                return recipientInput(r);
            }),
            actual_amount_recipient_commitments: 1,
            spend_commitments: [
                spendInput(note, side.asset, localProof, edgeIndex),
                fakeSpendInput(w.nonce(n + 4)),
                fakeSpendInput(w.nonce(n + 5)),
                fakeSpendInput(w.nonce(n + 6)),
            ],
            actual_amount_spend_commitments: 1,
            owner: {
                pub_key: owner.pubKey,
                nullifier_secret: owner.nullifierSecret,
                signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S },
            },
            auth: noAuth(),
            spend_selectors: joinSplitSelectors(),
        },
    });
    const tx = privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof, unshield: { recipient, note, side } });

    const wrappedBefore = await side.wrapper.read.balanceOf([recipient]);
    const underlyingBefore = await side.token.read.balanceOf([recipient]);
    await w.send(w.warptoad.write.transactPrivate([tx]));
    assert.equal(await side.wrapper.read.balanceOf([recipient]), wrappedBefore + note.amount, "unshielded into the wrapper");
    assert.equal(await w.warptoad.read.nullifiers([nullifiers[0]]) > 0n, true);

    await w.send(w.factory.write.unWrap([side.wrapper.address, note.amount, recipient], { account: owner.wallet.account }));
    assert.equal(await side.wrapper.read.balanceOf([recipient]), wrappedBefore, "wrapper burned");
    assert.equal(await side.token.read.balanceOf([recipient]), underlyingBefore + note.amount, "got the underlying");
}
