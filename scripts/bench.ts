/**
 * `pnpm bench`: proves and sends the main private tx shapes on a local hardhat chain and writes what they cost to
 * BENCHMARKS.md. Commit that file and a circuit or contract change shows up as numbers in the diff.
 *
 *   transfer       alice sends bob 300 of a 400 USDC note and keeps 100 change
 *   unshield       bob unshields those 300 to his eth address
 *   swaptoad fill  bob fills alice's order: 300 of her 400 USDC for 200 of his 500 DAI, 4 new notes
 *
 * Every slot of every tx carries a message, a note encrypted to its owner's view key or a fake one, the way a wallet
 * sends it, so the gas includes realistic calldata.
 *
 * Per tx it measures witness generation (noir_js, in this process), `bb prove` with the native binary and with
 * bb.js WASM (what a browser wallet runs), each in a process of its own so the peak memory is that proof's alone,
 * then the gas of `transactPrivate` and of `WarptoadVerifier.verify` called on its own. Times are the median of
 * BENCH_RUNS runs (default 3), memory the max. BENCH_WASM=0 skips the WASM prover, it is the slow one.
 *
 * BENCHMARKS.md gets one section per machine (cpu x ram x swap). The build, circuit and gas sections are machine
 * independent and rewritten on every run, a machine's section only when the bench runs on that machine.
 * Native peak memory needs GNU time at /usr/bin/time (`apt install time`), without it that column says n/a
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus, release, totalmem } from "node:os";
import { gunzipSync } from "node:zlib";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { bytesToHex, decodeFunctionData, toHex, type Address, type Hex } from "viem";
import { CIRCUIT_SIZE, JOIN_SPLIT_SELECTOR, MAX_TREE_DEPTH, SWAP_TOAD_SELECTOR } from "../src/constants.js";
import {
    hashCircuitComponentAuthSig,
    hashCommitment,
    hashFakeCommitment,
    hashFakeNullifier,
    hashNullifier,
    hashPublic,
    type CircuitSizeFields,
} from "../src/hashing.js";
import {
    emptyProof,
    fakeNote,
    fakeSpendInput,
    hashNote,
    joinSplitSelectors,
    merkleProofInput,
    noAuth,
    noUnshield,
    preCommitmentHashOf,
    pubRoots,
    recipientInput,
    sealedRecipientInput,
    sealNote,
    spendInput,
    toNoirInputs,
    unshieldInput,
} from "../src/proving.js";
import { deriveViewKey, encryptNote, fakeMessage, hashMessages } from "../src/messages.js";
import type { CircuitInputs, Note, UnshieldingCommitmentInput } from "../src/types.js";
import circuit from "../circuits/target/warptoad_v1.json" with { type: "json" };
import {
    connectSwapToad,
    DAI,
    nullifierSecretOf,
    privateTx,
    setupToken,
    signMessage,
    swapToadNote,
    swapToadOrder,
    swapToadStorageOf,
    USDC,
    type Party,
    type TokenSide,
} from "../test/swaptoad.js";
import { contractSizes, EIP_170_LIMIT, EIP_3860_LIMIT } from "./contractSizes.js";

const BENCH_FILE = "BENCHMARKS.md";
const CIRCUIT_PATH = "circuits/target/warptoad_v1.json";
const VK_PATH = "circuits/target/vk";
// cache/ is gitignored
const OUT_DIR = "cache/bench";
const RUNS = Number(process.env.BENCH_RUNS ?? 3);
const WASM = process.env.BENCH_WASM !== "0";
// BSD time has no -f, so this is false on macos too
const GNU_TIME = existsSync("/usr/bin/time") && spawnSync("/usr/bin/time", ["-f", "%M", "true"]).status === 0;
// a prover that hangs fails the bench instead of blocking it forever
const PROVER_TIMEOUT_MS = 30 * 60_000;

type ProverRun = { ms: number; peakKB?: number };
type Row = {
    name: string;
    witnessMs: number;
    witnessBytes: number;
    witnessGzBytes: number;
    native: ProverRun;
    wasm?: ProverRun & { initMs: number };
    txGas: bigint;
    verifyGas: bigint;
    proofBytes: number;
    publicInputs: number;
};

// ---------- measuring a proof ----------

function median(xs: number[]): number {
    const s = [...xs].sort((a, b) => a - b);
    return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

function maxOf(xs: (number | undefined)[]): number | undefined {
    return xs.some((x) => x === undefined) ? undefined : Math.max(...(xs as number[]));
}

/** `bb prove` as the CLI, wall time includes starting bb and loading the CRS. Writes `proof` and `public_inputs` to `dir` */
function nativeProve(witnessPath: string, dir: string): ProverRun {
    const args = ["prove", "-b", CIRCUIT_PATH, "-w", witnessPath, "-k", VK_PATH, "-o", dir, "-t", "evm"];
    const memPath = `${dir}/peak-kb`;
    const [cmd, ...cmdArgs] = GNU_TIME ? ["/usr/bin/time", "-f", "%M", "-o", memPath, "bb", ...args] : ["bb", ...args];
    const start = performance.now();
    const r = spawnSync(cmd, cmdArgs, { encoding: "utf8", timeout: PROVER_TIMEOUT_MS });
    const ms = performance.now() - start;
    if (r.status !== 0) throw new Error(`bb prove failed:\n${r.error ?? ""}\n${r.stdout}\n${r.stderr}`);
    return { ms, peakKB: GNU_TIME ? Number(readFileSync(memPath, "utf8").trim().split("\n").pop()) : undefined };
}

function wasmProve(witnessPath: string, proofPath: string): ProverRun & { initMs: number } {
    const r = spawnSync(process.execPath, ["scripts/benchWasmProve.ts", CIRCUIT_PATH, witnessPath, proofPath], { encoding: "utf8", timeout: PROVER_TIMEOUT_MS });
    if (r.status !== 0) throw new Error(`bb.js wasm prove failed:\n${r.error ?? ""}\n${r.stdout}\n${r.stderr}`);
    const { initMs, proveMs, peakKB } = JSON.parse(r.stdout.trim().split("\n").pop()!);
    return { ms: proveMs, peakKB, initMs };
}

/** the witness, then RUNS proofs of it with each prover. Returns the native proof and the public inputs bb saw */
async function measuredProve(name: string, inputs: CircuitInputs) {
    const dir = `${OUT_DIR}/${name.replaceAll(" ", "-")}`;
    mkdirSync(dir, { recursive: true });
    const noir = new Noir(circuit as CompiledCircuit);
    const witnessMs: number[] = [];
    let witness = new Uint8Array();
    for (let i = 0; i < RUNS; i++) {
        const start = performance.now();
        ({ witness } = await noir.execute(toNoirInputs(inputs) as InputMap));
        witnessMs.push(performance.now() - start);
    }
    const witnessPath = `${dir}/witness.gz`;
    writeFileSync(witnessPath, witness);

    const native: ProverRun[] = [];
    const wasm: (ProverRun & { initMs: number })[] = [];
    for (let i = 0; i < RUNS; i++) {
        console.log(`  ${name}: proof ${i + 1}/${RUNS}`);
        native.push(nativeProve(witnessPath, dir));
        if (WASM) wasm.push(wasmProve(witnessPath, `${dir}/proof-wasm`));
    }

    const publicInputsBytes = readFileSync(`${dir}/public_inputs`);
    const publicInputs: Hex[] = [];
    for (let i = 0; i < publicInputsBytes.length; i += 32) publicInputs.push(bytesToHex(publicInputsBytes.subarray(i, i + 32)));
    const proofBytes = readFileSync(`${dir}/proof`);
    return {
        proof: toHex(proofBytes),
        wasmProof: WASM ? toHex(readFileSync(`${dir}/proof-wasm`)) : undefined,
        publicInputs,
        metrics: {
            name,
            witnessMs: median(witnessMs),
            witnessBytes: gunzipSync(witness).length,
            witnessGzBytes: witness.length,
            native: { ms: median(native.map((r) => r.ms)), peakKB: maxOf(native.map((r) => r.peakKB)) },
            wasm: WASM
                ? { ms: median(wasm.map((r) => r.ms)), peakKB: maxOf(wasm.map((r) => r.peakKB)), initMs: median(wasm.map((r) => r.initMs)) }
                : undefined,
            proofBytes: proofBytes.length,
            publicInputs: publicInputs.length,
        },
    };
}

// ---------- the txs ----------

const w = await connectSwapToad();
assert.equal(w.live, false, "the bench deploys its own contracts, run it without --network");
const { alice, bob, gigaIndex, nonce } = w;
const verifier = await w.viem.getContractAt("WarptoadVerifier", await w.warptoad.read.verifier());
const rows: Row[] = [];

function viewKeyOf(p: Party) {
    return deriveViewKey(p.eddsaKey);
}

/** proves `inputs`, sends the tx, checks both proofs pass the verifier, and records what it all cost */
async function proveAndSend(
    name: string,
    inputs: CircuitInputs,
    makeTx: (proof: Hex) => Parameters<typeof w.warptoad.write.transactPrivate>[0][0],
) {
    const { proof, wasmProof, publicInputs, metrics } = await measuredProve(name, inputs);
    console.log(`  ${name}: verifying`);
    assert.equal(await verifier.read.verify([proof, publicInputs]), true, `${name}: native proof verifies`);
    if (wasmProof) assert.equal(await verifier.read.verify([wasmProof, publicInputs]), true, `${name}: wasm proof verifies`);
    // a standalone tx to the verifier, so with the 21k base cost and the calldata of the proof
    const verifyGas = await w.publicClient.estimateContractGas({
        address: verifier.address,
        abi: verifier.abi,
        functionName: "verify",
        args: [proof, publicInputs],
        account: w.deployer.account,
    });
    const hash = await w.send(w.warptoad.write.transactPrivate([makeTx(proof)]));
    const receipt = await w.publicClient.getTransactionReceipt({ hash });
    assert.equal(receipt.status, "success", `${name}: transactPrivate`);
    rows.push({ ...metrics, txGas: receipt.gasUsed, verifyGas });
}

/** shields `note` from `owner`'s wrapper balance, with the note encrypted to them like a wallet would */
async function shield(side: TokenSide, note: Note, owner: Party) {
    const message = await encryptNote(note, viewKeyOf(owner).publicKey);
    await w.send(w.warptoad.write.shield([w.factory.address, preCommitmentHashOf(note), note.amount, side.args, message], { account: owner.wallet.account }));
}

/** an output of a join_split: a note for someone's view key, or an unshield of the spent asset to an eth address */
type Out = { note: Note; to: Party } | { unshieldTo: Address; amount: bigint };

/** `owner` spends `spent` with join_split into `outs`, fakes fill the rest. An unshield has to be in slot 0 */
async function joinSplit(name: string, owner: Party, spent: Note, side: TokenSide, outs: Out[], n: number) {
    const localTree = await w.tree();
    const { proof: localProof, edgeIndex } = merkleProofInput(localTree, hashNote(spent));

    const recipients: Note[] = [];
    const recipientHashes: bigint[] = [];
    const messages: Hex[] = [];
    const unshielding: UnshieldingCommitmentInput[] = [];
    let unshield: { recipient: Address; note: Note; side: TokenSide } | undefined;
    for (let i = 0; i < CIRCUIT_SIZE; i++) {
        const out = outs[i];
        const fakeNonce = nonce(n + i);
        if (out === undefined) {
            recipients.push(fakeNote(fakeNonce));
            recipientHashes.push(hashFakeCommitment({ nonce: fakeNonce }));
            messages.push(await fakeMessage(fakeNonce));
            unshielding.push(noUnshield());
        } else if ("unshieldTo" in out) {
            assert.equal(i, 0, "unshields come first");
            // an unshield is a recipient note whose owner hash is the eth address. Nothing to tell anyone, but the
            // slot still gets a message so an unshield looks like any other tx
            const note: Note = { ownerHash: BigInt(out.unshieldTo), sharedNonce: 0n, assetId: spent.assetId, amount: out.amount };
            recipients.push(note);
            recipientHashes.push(hashNote(note));
            messages.push(await fakeMessage(fakeNonce));
            unshielding.push(unshieldInput(out.unshieldTo, spent.assetId, out.amount));
            unshield = { recipient: out.unshieldTo, note, side };
        } else {
            recipients.push(out.note);
            recipientHashes.push(hashNote(out.note));
            messages.push(await encryptNote(out.note, viewKeyOf(out.to).publicKey));
            unshielding.push(noUnshield());
        }
    }
    const fakeSpendNonces = Array.from({ length: CIRCUIT_SIZE - 1 }, (_, i) => nonce(n + CIRCUIT_SIZE + i));
    const nullifiers = [
        hashNullifier({ nullifierSecret: nullifierSecretOf(spent, owner), sharedNonce: spent.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: localProof.index }),
        ...fakeSpendNonces.map((k) => hashFakeNullifier({ nonce: k })),
    ] as CircuitSizeFields;
    const messageHashes = hashMessages(messages);
    const publicHash = hashPublic({ messageHashes, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes as CircuitSizeFields });
    const sig = signMessage(owner.eddsaKey, publicHash);

    const ts = await w.timeStamps();
    await proveAndSend(
        name,
        {
            pub_in: {
                roots: pubRoots(localTree.root, edgeIndex, gigaIndex),
                time_stamps: ts,
                public_hash: publicHash,
                message_hashes: messageHashes,
                unshielding_commitments: unshielding,
                nullifiers,
                recipient_commitments_hashes: recipientHashes as CircuitSizeFields,
            },
            priv_in: {
                recipient_commitments: recipients.map((r) => recipientInput(r)),
                actual_amount_recipient_commitments: outs.length,
                spend_commitments: [spendInput(spent, side.asset, localProof, edgeIndex), ...fakeSpendNonces.map((k) => fakeSpendInput(k))],
                actual_amount_spend_commitments: 1,
                owner: { pub_key: owner.pubKey, nullifier_secret: owner.nullifierSecret, signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S } },
                auth: noAuth(),
                spend_selectors: joinSplitSelectors(),
            },
        },
        (proof) => ({
            ...privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes: recipientHashes as CircuitSizeFields, proof, unshield }),
            messages,
        }),
    );
}

/** ClaudesLilSwapToadFill step 2, with messages: bob fills alice's order on `offered` with `bobDai` */
async function swapToadFill(name: string, usdc: TokenSide, dai: TokenSide) {
    const ts = await w.timeStamps();
    const authExpiry = ts.proof_expire_time_stamp + 86400n;
    const offered = swapToadNote(w, alice, { assetId: usdc.id, amount: USDC("400"), authExpiry }, 5000);
    const bobDai = swapToadNote(w, bob, { assetId: dai.id, amount: DAI("500"), authExpiry }, 5010);
    await shield(usdc, offered.note, alice);
    await shield(dai, bobDai.note, bob);

    // alice: the two notes she wants, a message for each, and the order over their hashes
    const aliceChange = swapToadNote(w, alice, { assetId: usdc.id, amount: USDC("100"), authExpiry }, 5020);
    const alicePayment = swapToadNote(w, alice, { assetId: dai.id, amount: DAI("200"), authExpiry }, 5030);
    const aliceMessages = [await encryptNote(aliceChange.note, viewKeyOf(alice).publicKey), await encryptNote(alicePayment.note, viewKeyOf(alice).publicKey)];
    const aliceMessageHashes = hashMessages(aliceMessages);
    const order = swapToadOrder({
        newCommitHashes: [hashNote(aliceChange.note), hashNote(alicePayment.note)],
        spendCommitHashes: [hashNote(offered.note)],
        messageHashes: aliceMessageHashes,
        expiry: ts.proof_expire_time_stamp + 3600n,
    });
    const orderSig = signMessage(offered.orderKey, hashCircuitComponentAuthSig({ authSigInputs: order }));
    const change = sealNote(aliceChange.note);
    const payment = sealNote(alicePayment.note);

    // bob
    const offeredStorage = swapToadStorageOf(offered.note);
    const localTree = await w.tree();
    const { proof: offeredProof, edgeIndex } = merkleProofInput(localTree, hashNote(offered.note));
    const { proof: daiProof } = merkleProofInput(localTree, hashNote(bobDai.note));
    const bobChange = swapToadNote(w, bob, { assetId: dai.id, amount: bobDai.note.amount - payment.amount, authExpiry }, 5040);
    const bobUsdc = swapToadNote(w, bob, { assetId: usdc.id, amount: offered.note.amount - change.amount, authExpiry }, 5050);
    const recipientHashes = [hashCommitment(change), hashCommitment(payment), hashNote(bobChange.note), hashNote(bobUsdc.note)] as CircuitSizeFields;
    const messages = [...aliceMessages, await encryptNote(bobChange.note, viewKeyOf(bob).publicKey), await encryptNote(bobUsdc.note, viewKeyOf(bob).publicKey)];
    const messageHashes = hashMessages(messages);
    const nullifiers = [
        hashNullifier({ nullifierSecret: offeredStorage.sharedNullifierSecret, sharedNonce: offered.note.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: offeredProof.index }),
        hashNullifier({ nullifierSecret: swapToadStorageOf(bobDai.note).sharedNullifierSecret, sharedNonce: bobDai.note.sharedNonce, gigaLeafIndex: gigaIndex, localLeafIndex: daiProof.index }),
        hashFakeNullifier({ nonce: nonce(5060) }),
        hashFakeNullifier({ nonce: nonce(5061) }),
    ] as CircuitSizeFields;
    const unshielding = [noUnshield(), noUnshield(), noUnshield(), noUnshield()];
    const publicHash = hashPublic({ messageHashes, unshieldingCommitments: unshielding, nullifiers, recipientCommitmentHashes: recipientHashes });
    const sig = signMessage(bobDai.owner.eddsaKey, publicHash);

    await proveAndSend(
        name,
        {
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
                recipient_commitments: [sealedRecipientInput(change), sealedRecipientInput(payment), recipientInput(bobChange.note), recipientInput(bobUsdc.note)],
                actual_amount_recipient_commitments: 4,
                spend_commitments: [
                    spendInput(offered.note, usdc.asset, offeredProof, edgeIndex, emptyProof(), offered.owner.ownerKeysHash),
                    spendInput(bobDai.note, dai.asset, daiProof, edgeIndex),
                    fakeSpendInput(nonce(5060)),
                    fakeSpendInput(nonce(5061)),
                ],
                actual_amount_spend_commitments: 2,
                owner: { pub_key: bobDai.owner.pubKey, nullifier_secret: bobDai.owner.nullifierSecret, signature: { x: sig.R8[0], y: sig.R8[1], scalar: sig.S } },
                auth: {
                    pub_key: offeredStorage.orderPubKey,
                    signature: { x: orderSig.R8[0], y: orderSig.R8[1], scalar: orderSig.S },
                    inputs: order,
                },
                spend_selectors: [SWAP_TOAD_SELECTOR, JOIN_SPLIT_SELECTOR, JOIN_SPLIT_SELECTOR, JOIN_SPLIT_SELECTOR],
            },
        },
        (proof) => ({ ...privateTx(w, { root: localTree.root, edgeIndex, ts, nullifiers, recipientHashes, proof }), messages }),
    );
}

console.log(`proving with ${RUNS} run(s) per prover${WASM ? "" : ", wasm skipped"}`);
const usdc = await setupToken(w, "USDC", "USD Coin", 6, alice, USDC("1000"));
const dai = await setupToken(w, "DAI", "Dai Stablecoin", 18, bob, DAI("500"));

const aliceDeposit: Note = { ownerHash: alice.ownerHash, sharedNonce: nonce(100), assetId: usdc.id, amount: USDC("400") };
await shield(usdc, aliceDeposit, alice);
const bobNote: Note = { ownerHash: bob.ownerHash, sharedNonce: nonce(201), assetId: usdc.id, amount: USDC("300") };
const aliceChange: Note = { ownerHash: alice.ownerHash, sharedNonce: nonce(202), assetId: usdc.id, amount: USDC("100") };
await joinSplit("transfer", alice, aliceDeposit, usdc, [{ note: bobNote, to: bob }, { note: aliceChange, to: alice }], 1000);
await joinSplit("unshield", bob, bobNote, usdc, [{ unshieldTo: bob.wallet.account.address, amount: bobNote.amount }], 2000);
await swapToadFill("swaptoad fill", usdc, dai);

// ---------- gas of everything else, from the receipts of what ran above ----------

const otherGas: { name: string; gas: bigint }[] = [];
{
    const deploys: Record<string, string> = {
        [w.warptoad.address.toLowerCase()]: "deploy Warptoad",
        [verifier.address.toLowerCase()]: "deploy WarptoadVerifier",
        [w.factory.address.toLowerCase()]: "deploy WrapperFactory",
    };
    const seen = new Set<string>();
    const latest = await w.publicClient.getBlockNumber();
    for (let b = 0n; b <= latest; b++) {
        const block = await w.publicClient.getBlock({ blockNumber: b, includeTransactions: true });
        for (const tx of block.transactions) {
            const receipt = await w.publicClient.getTransactionReceipt({ hash: tx.hash });
            let name: string | undefined;
            if (receipt.contractAddress) name = deploys[receipt.contractAddress.toLowerCase()];
            else if (tx.to?.toLowerCase() === w.factory.address.toLowerCase() && functionName(w.factory.abi, tx.input) === "wrap") name = "wrap, first time (deploys the wrapper)";
            else if (tx.to?.toLowerCase() === w.warptoad.address.toLowerCase() && functionName(w.warptoad.abi, tx.input) === "shield") name = "shield (with an encrypted note)";
            if (name && !seen.has(name)) {
                seen.add(name);
                otherGas.push({ name, gas: receipt.gasUsed });
            }
        }
    }
    otherGas.sort((a, b) => a.name.localeCompare(b.name));
}
await w.close();

function functionName(abi: readonly unknown[], data: Hex): string | undefined {
    try {
        return decodeFunctionData({ abi: abi as never, data }).functionName;
    } catch {
        return undefined;
    }
}

// ---------- what it ran on and was built with ----------

function firstLine(cmd: string, args: string[]): string {
    try {
        return execFileSync(cmd, args, { encoding: "utf8" }).trim().split("\n")[0];
    } catch {
        return "not found";
    }
}

function packageVersion(name: string): string {
    return JSON.parse(readFileSync(`node_modules/${name}/package.json`, "utf8")).version;
}

function swapGiB(): string {
    try {
        const kb = Number(/SwapTotal:\s+(\d+)/.exec(readFileSync("/proc/meminfo", "utf8"))![1]);
        return `${(kb / 2 ** 20).toFixed(1)} GiB swap`;
    } catch {
        return "unknown swap";
    }
}

const cpu = cpus()[0].model.trim();
const machine = `${cpu} · ${cpus().length} threads · ${(totalmem() / 2 ** 30).toFixed(1)} GiB RAM · ${swapGiB()}`;

const gates = JSON.parse(execFileSync("bb", ["gates", "-b", CIRCUIT_PATH], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })).functions[0] as {
    acir_opcodes: number;
    circuit_size: number;
};
const vkHash = readFileSync("circuits/target/vk_hash").toString("hex");

type BuildInfo = { solcLongVersion: string; input: { settings: { optimizer?: { enabled?: boolean; runs?: number }; viaIR?: boolean; evmVersion?: string } } };
const buildInfos = new Map<string, BuildInfo>();
function buildInfo(id: string): BuildInfo {
    if (!buildInfos.has(id)) buildInfos.set(id, JSON.parse(readFileSync(`artifacts/build-info/${id}.json`, "utf8")));
    return buildInfos.get(id)!;
}
function optimizerOf(id: string): string {
    const { optimizer, viaIR } = buildInfo(id).input.settings;
    return `${optimizer?.enabled ? `on, ${optimizer.runs} runs` : "off"}${viaIR ? ", via IR" : ""}`;
}
// mocks only exist for the tests
const sizes = contractSizes().filter((c) => !c.sourceName.startsWith("contracts/mocks/"));
const warptoadBuild = sizes.find((c) => c.name === "Warptoad")!.buildInfoId;

// ---------- BENCHMARKS.md ----------

const n = (x: number | bigint) => x.toLocaleString("en-US");
const sec = (ms: number) => `${(ms / 1000).toFixed(2)} s`;
const mib = (kb?: number) => (kb === undefined ? "n/a" : `${n(Math.round(kb / 1024))} MiB`);
const kib = (bytes: number) => `${n(Math.round(bytes / 1024))} KiB`;
const pct = (x: number, of: number) => `${((x / of) * 100).toFixed(1)}%`;
const table = (head: string[], align: string[], body: string[][]) =>
    [`| ${head.join(" | ")} |`, `| ${align.join(" | ")} |`, ...body.map((r) => `| ${r.join(" | ")} |`)].join("\n");

const { solcLongVersion, input } = buildInfo(warptoadBuild);
const shared = `# Benchmarks

Written by \`pnpm bench\` (scripts/bench.ts), don't edit by hand. Build, circuit and gas are rewritten on every run, a
machine's section only when the bench runs on that machine.

## Build

solc ${solcLongVersion}, evm ${input.settings.evmVersion}, Warptoad optimizer ${optimizerOf(warptoadBuild)}

${table(
    ["contract", "runtime", "of EIP-170", "initcode", "of EIP-3860", "optimizer"],
    ["---", "---:", "---:", "---:", "---:", "---"],
    sizes.map((c) => [c.name, n(c.bytes), pct(c.bytes, EIP_170_LIMIT), n(c.initBytes), pct(c.initBytes, EIP_3860_LIMIT), optimizerOf(c.buildInfoId)]),
)}

## Circuit

CIRCUIT_SIZE ${CIRCUIT_SIZE}, MAX_TREE_DEPTH ${MAX_TREE_DEPTH}. nargo ${firstLine("nargo", ["--version"]).replace("nargo version = ", "")}, bb ${firstLine("bb", ["--version"])},
bb.js ${packageVersion("@aztec/bb.js")}, noir_js ${packageVersion("@noir-lang/noir_js")}

${table(
    ["ACIR opcodes", "gates", "padded to", "proof", "public inputs", "vk hash"],
    ["---:", "---:", "---:", "---:", "---:", "---"],
    [[n(gates.acir_opcodes), n(gates.circuit_size), `2^${Math.ceil(Math.log2(gates.circuit_size))}`, `${n(rows[0].proofBytes)} bytes`, String(rows[0].publicInputs), `\`${vkHash.slice(0, 16)}\``]],
)}

## Gas

Hardhat chain, the setup the private txs below needed. Those are in the machine tables, next to their proofs

${table(["tx", "gas"], ["---", "---:"], otherGas.map((g) => [g.name, n(g.gas)]))}

## Machines
`;

const section = `<!-- machine: ${machine} -->
### ${machine}

${process.platform} ${release()}, vk \`${vkHash.slice(0, 16)}\`, Warptoad optimizer ${optimizerOf(warptoadBuild)}. Median of ${RUNS} run(s),
peak memory is the max. Every slot carries a message.${WASM ? ` bb.js WASM startup (compile + CRS) takes another ${sec(median(rows.map((r) => r.wasm!.initMs)))}, not in its column.` : ""}
verify gas is \`WarptoadVerifier.verify\` sent as a tx of its own, so with the 21k base and the proof's calldata

${table(
    ["tx", "witness gen", "witness (gz)", "bb prove native", "peak mem", "bb.js prove wasm", "peak mem", "tx gas", "verify gas"],
    ["---", "---:", "---:", "---:", "---:", "---:", "---:", "---:", "---:"],
    rows.map((r) => [
        r.name,
        sec(r.witnessMs),
        `${kib(r.witnessBytes)} (${kib(r.witnessGzBytes)})`,
        sec(r.native.ms),
        mib(r.native.peakKB),
        r.wasm ? sec(r.wasm.ms) : "skipped",
        r.wasm ? mib(r.wasm.peakKB) : "skipped",
        n(r.txGas),
        n(r.verifyGas),
    ]),
)}
<!-- /machine -->`;

const SECTION = /<!-- machine: (.*?) -->\n[\s\S]*?<!-- \/machine -->/g;
const machines = new Map<string, string>();
if (existsSync(BENCH_FILE)) {
    for (const m of readFileSync(BENCH_FILE, "utf8").matchAll(SECTION)) machines.set(m[1], m[0]);
}
machines.set(machine, section);
const sorted = [...machines.keys()].sort().map((k) => machines.get(k)!);
writeFileSync(BENCH_FILE, `${shared}\n${sorted.join("\n\n")}\n`);
console.log(`\nwrote ${BENCH_FILE}, section "${machine}"\n`);
console.log(section);
