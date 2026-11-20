/**
 * One bb.js WASM proof in a process of its own, so scripts/bench.ts gets a clean peak memory number for it. That is
 * the backend a browser wallet proves with, node would pick the native bb binary.
 *
 *   node scripts/benchWasmProve.ts <circuit.json> <witness.gz> <proof out>
 *
 * Prints one JSON line: how long `generateProof` took, how long the backend took to start before that (wasm compile
 * and CRS load, a wallet pays it once) and the peak RSS of this whole node process in KB
 */
import { readFileSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { Barretenberg, BackendType, UltraHonkBackend } from "@aztec/bb.js";

const [circuitPath, witnessPath, proofPath] = process.argv.slice(2);
const { bytecode } = JSON.parse(readFileSync(circuitPath, "utf8")) as { bytecode: string };
const witness = readFileSync(witnessPath);

const start = performance.now();
const bb = await Barretenberg.new({ threads: cpus().length, backend: BackendType.Wasm });
const backend = new UltraHonkBackend(bytecode, bb);
const ready = performance.now();
const { proof } = await backend.generateProof(witness, { verifierTarget: "evm" });
const done = performance.now();
await bb.destroy();

writeFileSync(proofPath, proof);
console.log(JSON.stringify({ initMs: ready - start, proveMs: done - ready, peakKB: process.resourceUsage().maxRSS }));
// wasm worker threads can outlive destroy() and keep node up, the parent waits on this process
process.exit(0);
