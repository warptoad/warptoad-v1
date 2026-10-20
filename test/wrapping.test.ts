/**
 * The contracts without a prover: ChainConfig, WrapperFactory wrap/unWrap, Warptoad.shield and the checks
 * `transactPrivate` does before it reaches the verifier. The bridged unshield path is driven by impersonating
 * Warptoad, since on one chain no real proof can produce a note for a wrapper that does not exist here yet
 */
import assert from "node:assert/strict";
import { before, beforeEach, describe, it } from "node:test";
import { artifacts, network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import { getAddress, parseEventLogs, type Address, type Hex } from "viem";
import { chainName, chainConfigArgs, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";
import { CIRCUIT_SIZE } from "../src/constants.js";
import { hashAssetId, hashCommitment } from "../src/hashing.js";
import {
    assetOf,
    computeWrapperAddress,
    encodeWrapperArgs,
    encodeWrapperDeployArgs,
    formatWrapperName,
    formatWrapperSymbol,
    hashWrapperAssetHash,
    resolveAsset,
    type WrapperDeployInfo,
} from "../src/assets.js";
import type { WrapperERC20Contract } from "../src/types.js";
import { deployInfra, deployWarptoad, wrap, ZERO_ADDRESS, type Deployment, type Infra } from "./fixtures.js";

describe("Warptoad contracts", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, other] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();
    const chainLabels = chainName(chainId);

    let infra: Infra;
    let d: Deployment;
    /** [first, last] giga index range the factory bakes into every assetId, 0..0 until it gets a real one */
    let range: readonly [bigint, bigint];

    before(async () => {
        infra = await deployInfra(viem, publicClient, deployer);
    });

    beforeEach(async () => {
        d = await deployWarptoad(viem, infra);
        range = await d.factory.read.gigaIndexRange();
    });

    /** the asset a wrapper of `underlying` issued by this deployment's factory has */
    function assetFor(wrapper: Address, underlying: Address) {
        return assetOf({ wrapperFactory: d.factory.address, wrapper, underlying, firstGigaIndex: range[0], lastGigaIndex: range[1] });
    }

    async function usdc() {
        const token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
        await token.write.mint([deployer.account.address, 1_000_000n]);
        await token.write.approve([d.factory.address, 1_000_000n]);
        return token;
    }

    describe("ChainConfig", () => {
        it("answers for this chain from the table it was deployed with", async () => {
            // uint64 decodes as bigint
            assert.equal(await d.chainConfig.read.gigaIndex(), 0n);
            assert.deepEqual(await d.chainConfig.read.info(), { gigaIndex: 0n, chainSymbol: chainLabels.symbol, chainName: chainLabels.name });
            assert.deepEqual(await d.chainConfig.read.infoOf([BigInt(chainId)]), await d.chainConfig.read.info());
        });

        it("rejects chains that are not in the table", async () => {
            await assert.rejects(d.chainConfig.read.infoOf([1n]), /UnknownChain/);
        });

        it("rejects a malformed table", async () => {
            const [chainIds, infos] = chainConfigArgs(["local"]);
            await assert.rejects(viem.deployContract("ChainConfig", [chainIds, []]), /LengthMismatch/);
            await assert.rejects(viem.deployContract("ChainConfig", [[...chainIds, ...chainIds], [...infos, ...infos]]), /DuplicateChainId/);
            await assert.rejects(viem.deployContract("ChainConfig", [chainIds, [{ ...infos[0], chainName: "" }]]), /EmptyChainName/);
        });

        it("has the same table for every production chain and a separate local one", async () => {
            const [chainIds] = chainConfigArgs();
            assert.equal(chainIds.length, 12);
            assert.equal(chainIds.includes(BigInt(chainId)), false, "31337 never ships in a production ChainConfig");
        });

        it("makes Warptoad and the factory refuse to deploy on a chain missing from the table", async () => {
            // mainnet + sepolia only, so 31337 is unknown
            const [chainIds, infos] = chainConfigArgs();
            const production = await viem.deployContract("ChainConfig", [chainIds, infos]);
            await assert.rejects(
                viem.deployContract("Warptoad", [d.verifier.address, BigInt(CIRCUIT_SIZE), production.address], {
                    libraries: { SkinnyIMTPoseidon2WriteStorage: infra.skinnyIMT },
                }),
                /UnknownChain/,
            );
            await assert.rejects(
                viem.deployContract("WrapperFactory", [SYMBOL_PREFIX, NAME_PREFIX, d.warptoad.address, production.address]),
                /UnknownChain/,
            );
        });

        it("gives Warptoad and the factory their chain's giga index", async () => {
            assert.equal(d.gigaIndex, 0n);
            // the factory reads it from Warptoad, so both agree by construction. The constructor only takes the config address
            assert.equal(await d.warptoad.read.gigaIndex(), 0n);
        });
    });

    describe("wrap", () => {
        let token: ContractReturnType<"MockERC20">;

        beforeEach(async () => {
            token = await usdc();
        });

        it("names the wrapper from the chain config", async () => {
            const wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            assert.equal(await wrapper.read.symbol(), formatWrapperSymbol("USDC", chainLabels.symbol));
            assert.equal(await wrapper.read.symbol(), `${SYMBOL_PREFIX}USDC@${chainLabels.symbol}`);
            assert.equal(await wrapper.read.name(), formatWrapperName("USD Coin", chainLabels.name));
            assert.equal(await wrapper.read.name(), `Wrapped ${NAME_PREFIX} USD Coin ${chainLabels.name}`);
        });

        it("mirrors the underlying's decimals and remembers where it came from", async () => {
            const wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            assert.equal(await wrapper.read.decimals(), 6);
            assert.equal(getAddress(await wrapper.read.underlying()), getAddress(token.address));
            assert.equal(getAddress(await wrapper.read.factory()), getAddress(d.factory.address));
            assert.equal(await wrapper.read.originGigaIndex(), 0n);
        });

        it("mints 1:1 and vaults the collateral in the factory", async () => {
            const wrapper = await wrap(viem, d,token.address, 1000n, other.account.address, deployer.account.address);
            assert.equal(await wrapper.read.balanceOf([other.account.address]), 1000n);
            assert.equal(await wrapper.read.totalSupply(), 1000n);
            assert.equal(await token.read.balanceOf([d.factory.address]), 1000n);
        });

        it("reuses the wrapper on subsequent wraps", async () => {
            const first = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            const second = await wrap(viem, d,token.address, 500n, deployer.account.address, deployer.account.address);
            assert.equal(second.address, first.address);
            assert.equal(await first.read.totalSupply(), 1500n);
        });

        it("is listed both ways, under this chain's giga index only", async () => {
            const wrapper = await wrap(viem, d, token.address, 1000n, deployer.account.address, deployer.account.address);
            assert.equal(getAddress(await d.factory.read.wrappers([token.address, 0n])), getAddress(wrapper.address));
            assert.deepEqual(await d.factory.read.underlyings([wrapper.address]), [getAddress(token.address), 0n]);
            // nothing under another origin, and the underlying itself is not a wrapper
            assert.equal(await d.factory.read.wrappers([token.address, 1n]), ZERO_ADDRESS);
            assert.deepEqual(await d.factory.read.underlyings([token.address]), [ZERO_ADDRESS, 0n]);
        });

        it("puts the wrapper on the CREATE2 address the sdk predicts", async () => {
            const wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            const { bytecode } = await artifacts.readArtifact("WrapperERC20");
            const predicted = computeWrapperAddress({
                wrapperFactory: d.factory.address,
                creationCode: bytecode,
                underlying: token.address,
                originGigaIndex: 0n,
                name: formatWrapperName("USD Coin", chainLabels.name),
                symbol: formatWrapperSymbol("USDC", chainLabels.symbol),
                decimals: 6,
            });
            assert.equal(getAddress(wrapper.address), getAddress(predicted));
        });

        it("registers the asset on Warptoad and the wrapper on itself, so an assetId resolves with eth_calls only", async () => {
            const wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            const asset = assetFor(wrapper.address, token.address);
            const assetId = hashAssetId(asset);
            const wrapperAssetHash = hashWrapperAssetHash({ wrapper: wrapper.address, underlying: token.address });

            const [factory, storedHash] = await d.warptoad.read.assetSources([assetId]);
            assert.equal(getAddress(factory), getAddress(d.factory.address));
            assert.equal(storedHash, wrapperAssetHash);
            assert.equal(getAddress(await d.factory.read.wrapperOf([wrapperAssetHash])), getAddress(wrapper.address));

            const resolved = await resolveAsset(d.warptoad, publicClient, assetId);
            assert.deepEqual(resolved.asset, asset);
            assert.equal(getAddress(resolved.wrapper), getAddress(wrapper.address));
            assert.deepEqual(resolved.deployInfo, {
                underlying: getAddress(token.address),
                originGigaIndex: 0n,
                name: await wrapper.read.name(),
                symbol: await wrapper.read.symbol(),
                decimals: 6,
            });
            await assert.rejects(resolveAsset(d.warptoad, publicClient, assetId + 1n), /not registered/);
        });

        it("reads legacy bytes32 metadata", async () => {
            const legacy = await viem.deployContract("MockBytes32MetadataERC20");
            await legacy.write.mint([deployer.account.address, 1000n]);
            await legacy.write.approve([d.factory.address, 1000n]);
            const wrapper = await wrap(viem, d,legacy.address, 1000n, deployer.account.address, deployer.account.address);
            assert.equal(await wrapper.read.symbol(), formatWrapperSymbol("LGCY", chainLabels.symbol));
            assert.equal(await wrapper.read.name(), formatWrapperName("Legacy Token", chainLabels.name));
        });

        it("falls back to the address when a token exposes no metadata", async () => {
            const bare = await viem.deployContract("MockNoMetadataERC20");
            await bare.write.mint([deployer.account.address, 1000n]);
            await bare.write.approve([d.factory.address, 1000n]);
            const wrapper = await wrap(viem, d,bare.address, 1000n, deployer.account.address, deployer.account.address);
            assert.equal((await wrapper.read.symbol()).toLowerCase(), formatWrapperSymbol(bare.address, chainLabels.symbol).toLowerCase());
            // No readable decimals() means the conventional 18.
            assert.equal(await wrapper.read.decimals(), 18);
        });

        it("keeps both levels straight when a wrapper is itself wrapped", async () => {
            const inner = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            await inner.write.approve([d.factory.address, 500n]);
            const outer = await wrap(viem, d,inner.address, 500n, deployer.account.address, deployer.account.address);

            assert.notEqual(outer.address, inner.address);
            // Each level redeems for its own underlying, neither registry entry clobbers the other
            assert.deepEqual(await d.factory.read.underlyings([outer.address]), [getAddress(inner.address), 0n]);
            assert.deepEqual(await d.factory.read.underlyings([inner.address]), [getAddress(token.address), 0n]);
            assert.equal(await inner.read.balanceOf([deployer.account.address]), 500n);
            assert.equal(await inner.read.balanceOf([d.factory.address]), 500n);

            await d.factory.write.unWrap([outer.address, 500n, deployer.account.address]);
            assert.equal(await inner.read.balanceOf([deployer.account.address]), 1000n);
            assert.equal(await outer.read.totalSupply(), 0n);
        });
    });

    describe("unWrap", () => {
        let token: ContractReturnType<"MockERC20">;
        let wrapper: WrapperERC20Contract;

        beforeEach(async () => {
            token = await usdc();
            wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
        });

        it("burns the wrapper and releases the collateral", async () => {
            await d.factory.write.unWrap([wrapper.address, 400n, other.account.address]);
            assert.equal(await wrapper.read.balanceOf([deployer.account.address]), 600n);
            assert.equal(await wrapper.read.totalSupply(), 600n);
            assert.equal(await token.read.balanceOf([other.account.address]), 400n);
            assert.equal(await token.read.balanceOf([d.factory.address]), 600n);
        });

        it("round-trips the full balance with nothing left over", async () => {
            await d.factory.write.unWrap([wrapper.address, 1000n, deployer.account.address]);
            assert.equal(await wrapper.read.totalSupply(), 0n);
            assert.equal(await token.read.balanceOf([d.factory.address]), 0n);
            assert.equal(await token.read.balanceOf([deployer.account.address]), 1_000_000n);
        });

        it("rejects a token this factory did not issue", async () => {
            await assert.rejects(d.factory.write.unWrap([token.address, 1n, deployer.account.address]), /no underlying token found/);
        });

        it("lets only the factory mint or burn the wrapper", async () => {
            await assert.rejects(wrapper.write.mint([deployer.account.address, 1n]), /OnlyFactory/);
            await assert.rejects(wrapper.write.burn([deployer.account.address, 1n]), /OnlyFactory/);
        });

        it("lets only Warptoad shield or unshield through the factory", async () => {
            const args = encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address });
            await assert.rejects(d.factory.write.shield([deployer.account.address, 1n, args]), /OnlyWarptoad/);
            await assert.rejects(d.factory.write.unShield([deployer.account.address, 1n, args]), /OnlyWarptoad/);
        });
    });

    describe("shield", () => {
        let token: ContractReturnType<"MockERC20">;
        let wrapper: WrapperERC20Contract;
        let args: Hex;
        let treeId: bigint;

        beforeEach(async () => {
            token = await usdc();
            wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            args = encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address });
            // Derived from a storage slot at init, so ask the contract rather than hardcode it.
            treeId = await d.warptoad.read.commitmentTreeId();
        });

        it("burns the wrapper and inserts the commitment as a leaf", async () => {
            const hash = await d.warptoad.write.shield([d.factory.address, 42n, 400n, args, "0x"]);
            assert.equal(await wrapper.read.balanceOf([deployer.account.address]), 600n);

            // Computed with the js Poseidon2 (same one the circuit uses), so this also pins the etched Yul
            // contract at POSEIDON2_YUL to the circuit's hash_3, for both the assetId and the commitment
            const assetId = hashAssetId(assetFor(wrapper.address, token.address));
            const commitment = hashCommitment({ preCommitmentHash: 42n, assetId, amount: 400n });
            assert.deepEqual(await d.warptoad.read.getSkinnyLeaves([treeId, 0n, 1n]), [commitment]);

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const [shielded] = parseEventLogs({ abi: d.warptoad.abi, eventName: "Shielded", logs: receipt.logs });
            assert.equal(shielded.args.assetId, assetId);
            assert.equal(shielded.args.commitment, commitment);
            assert.equal(shielded.args.amount, 400n);
            const [message] = parseEventLogs({ abi: d.warptoad.abi, eventName: "Message", logs: receipt.logs });
            assert.equal(message.args.commitment, commitment);
        });

        it("records every root with the tree size at that time", async () => {
            await d.warptoad.write.shield([d.factory.address, 42n, 400n, args, "0x"]);
            const root = await d.warptoad.read.getSkinnyRoot([treeId]);
            assert.equal(await d.warptoad.read.localRoots([root]), 1n);
            assert.equal(await d.warptoad.read.localRoots([root + 1n]), 0n);
        });

        it("rejects wrapper args that do not point at a wrapper", async () => {
            // the factory tries to burn on the underlying, which has no burn
            const bad = encodeWrapperArgs({ wrapper: token.address, underlying: token.address });
            await assert.rejects(d.warptoad.write.shield([d.factory.address, 42n, 1n, bad, "0x"]));
            // nothing got inserted: the tree still has the empty root, which the constructor records as size 0
            assert.equal(await d.warptoad.read.getSkinnyRoot([treeId]), 0n);
            assert.equal(await d.warptoad.read.localRoots([0n]), 1n);
        });

        it("rejects more than the shielder holds", async () => {
            await assert.rejects(d.warptoad.write.shield([d.factory.address, 42n, 1001n, args, "0x"]), /ERC20InsufficientBalance/);
        });
    });

    describe("unShield of a wrapper bridged from another chain", () => {
        let token: ContractReturnType<"MockERC20">;
        let local: WrapperERC20Contract;
        let creationCode: Hex;
        /** the same USDC address, but wrapped on gigaIndex 1. The factory there formatted the names with its chain */
        let bridged: WrapperDeployInfo;
        let bridgedWrapper: Address;
        let factoryAsWarptoad: Deployment["factory"];

        before(async () => {
            ({ bytecode: creationCode } = await artifacts.readArtifact("WrapperERC20"));
        });

        beforeEach(async () => {
            token = await usdc();
            local = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            bridged = {
                underlying: token.address,
                originGigaIndex: 1n,
                name: formatWrapperName("USD Coin", "Arbitrum"),
                symbol: formatWrapperSymbol("USDC", "arb"),
                decimals: 6,
            };
            bridgedWrapper = computeWrapperAddress({ wrapperFactory: d.factory.address, creationCode, ...bridged });

            // only Warptoad may call unShield, and Warptoad only does so after a valid proof. Stand in for it
            const testClient = await viem.getTestClient();
            await testClient.impersonateAccount({ address: d.warptoad.address });
            await testClient.setBalance({ address: d.warptoad.address, value: 10n ** 18n });
            const wallet = await viem.getWalletClient(d.warptoad.address);
            factoryAsWarptoad = await viem.getContractAt("WrapperFactory", d.factory.address, { client: { wallet } });
        });

        it("deploys the wrapper at the address its args commit to and mints", async () => {
            assert.equal(await publicClient.getCode({ address: bridgedWrapper }), undefined, "not there yet");
            const args = encodeWrapperDeployArgs(bridgedWrapper, bridged);
            await factoryAsWarptoad.write.unShield([other.account.address, 300n, args]);

            const wrapper = await viem.getContractAt("WrapperERC20", bridgedWrapper);
            assert.equal(await wrapper.read.balanceOf([other.account.address]), 300n);
            assert.equal(await wrapper.read.name(), bridged.name);
            assert.equal(await wrapper.read.symbol(), bridged.symbol);
            assert.equal(await wrapper.read.decimals(), 6);
            assert.equal(await wrapper.read.originGigaIndex(), 1n);
            assert.equal(getAddress(await wrapper.read.underlying()), getAddress(token.address));
            // a different token than the locally wrapped one, same underlying address, filed under its own origin
            assert.notEqual(getAddress(bridgedWrapper), getAddress(local.address));
            assert.equal(getAddress(await d.factory.read.wrappers([token.address, 1n])), getAddress(bridgedWrapper));
            assert.equal(getAddress(await d.factory.read.wrappers([token.address, 0n])), getAddress(local.address));
            assert.deepEqual(await d.factory.read.underlyings([bridgedWrapper]), [getAddress(token.address), 1n]);
            assert.equal(await local.read.totalSupply(), 1000n);
        });

        it("registers the bridged asset like a local wrap does", async () => {
            await factoryAsWarptoad.write.unShield([other.account.address, 300n, encodeWrapperDeployArgs(bridgedWrapper, bridged)]);
            const resolved = await resolveAsset(d.warptoad, publicClient, hashAssetId(assetFor(bridgedWrapper, token.address)));
            assert.equal(getAddress(resolved.wrapper), getAddress(bridgedWrapper));
            assert.deepEqual(resolved.deployInfo, { ...bridged, underlying: getAddress(token.address) });
        });

        it("only deploys once, later unshields just mint", async () => {
            const args = encodeWrapperDeployArgs(bridgedWrapper, bridged);
            await factoryAsWarptoad.write.unShield([other.account.address, 300n, args]);
            // the short args are enough once the wrapper exists
            await factoryAsWarptoad.write.unShield([other.account.address, 200n, encodeWrapperArgs({ wrapper: bridgedWrapper, underlying: token.address })]);
            const wrapper = await viem.getContractAt("WrapperERC20", bridgedWrapper);
            assert.equal(await wrapper.read.balanceOf([other.account.address]), 500n);
        });

        it("rejects deploy args that do not hash to the wrapper address, before paying for the deploy", async () => {
            const wrongName = encodeWrapperDeployArgs(bridgedWrapper, { ...bridged, name: "Wrapped Warptoad USD Coin Optimism" });
            await assert.rejects(factoryAsWarptoad.write.unShield([other.account.address, 300n, wrongName]), /does not match expected wrapper/);
            const wrongOrigin = encodeWrapperDeployArgs(bridgedWrapper, { ...bridged, originGigaIndex: 2n });
            await assert.rejects(factoryAsWarptoad.write.unShield([other.account.address, 300n, wrongOrigin]), /does not match expected wrapper/);
            assert.equal(await publicClient.getCode({ address: bridgedWrapper }), undefined);
        });

        it("can not be unwrapped here: the underlying is on the origin chain", async () => {
            await factoryAsWarptoad.write.unShield([other.account.address, 300n, encodeWrapperDeployArgs(bridgedWrapper, bridged)]);
            await assert.rejects(
                d.factory.write.unWrap([bridgedWrapper, 300n, other.account.address], { account: other.account }),
                /only unwrap on the same wrapperFactory on the same chain/,
            );
            // while the locally wrapped one still can
            await d.factory.write.unWrap([local.address, 1000n, deployer.account.address]);
            assert.equal(await token.read.balanceOf([d.factory.address]), 0n);
            // the 300 bridged wrapper tokens still exist, backed by nothing on this chain by design
            assert.equal(await (await viem.getContractAt("WrapperERC20", bridgedWrapper)).read.totalSupply(), 300n);
        });

        it("can be shielded again here, into the bridged asset", async () => {
            await factoryAsWarptoad.write.unShield([other.account.address, 300n, encodeWrapperDeployArgs(bridgedWrapper, bridged)]);
            const args = encodeWrapperArgs({ wrapper: bridgedWrapper, underlying: token.address });
            const hash = await d.warptoad.write.shield([d.factory.address, 42n, 300n, args, "0x"], { account: other.account });
            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const [shielded] = parseEventLogs({ abi: d.warptoad.abi, eventName: "Shielded", logs: receipt.logs });
            assert.equal(shielded.args.assetId, hashAssetId(assetFor(bridgedWrapper, token.address)));
            assert.notEqual(shielded.args.assetId, hashAssetId(assetFor(local.address, token.address)));
        });
    });

    describe("transactPrivate before the verifier", () => {
        let root: bigint;
        let now: bigint;

        const zeros = () => new Array<bigint>(CIRCUIT_SIZE).fill(0n);
        const noUnshield = () => new Array(CIRCUIT_SIZE).fill(null).map(() => ({ recipient: 0n, amount: 0n, assetId: 0n }));
        const noTargets = () => new Array(CIRCUIT_SIZE).fill(null).map(() => ({ wrapperFactory: ZERO_ADDRESS as Address, wrapperArgs: "0x" as Hex }));

        /** everything valid except the proof, so each test breaks one thing */
        const validTx = () => ({
            roots: { localRoot: root, localEdgeIndex: 0n, gigaRoot: 0n, gigaEdgeIndex: 0n },
            timeStamps: { proofExpireTimeStamp: now + 3600n, historicTimeStamp: now - 3600n },
            unshieldingCommitments: noUnshield(),
            unshieldTargets: noTargets(),
            // nullifiers get stored before anything else is checked, so they have to be distinct
            nullifiers: [1n, 2n, 3n, 4n],
            recipientCommitmentsHashes: zeros(),
            messages: new Array<Hex>(CIRCUIT_SIZE).fill("0x"),
            publicHash: 0n,
            proof: "0x" as Hex,
        });

        beforeEach(async () => {
            const token = await usdc();
            const wrapper = await wrap(viem, d,token.address, 1000n, deployer.account.address, deployer.account.address);
            await d.warptoad.write.shield([d.factory.address, 42n, 400n, encodeWrapperArgs({ wrapper: wrapper.address, underlying: token.address }), "0x"]);
            root = await d.warptoad.read.getSkinnyRoot([await d.warptoad.read.commitmentTreeId()]);
            now = (await publicClient.getBlock()).timestamp;
        });

        it("lays out the public inputs in the circuit's order", async () => {
            const unshielding = noUnshield();
            unshielding[1] = { recipient: 0x11n, amount: 0x12n, assetId: 0x13n };
            const nullifiers = zeros();
            nullifiers[2] = 0x22n;
            const recipients = zeros();
            recipients[3] = 0x33n;

            const inputs = await d.warptoad.read.formatPublicInputs([
                { localRoot: 1n, localEdgeIndex: 2n, gigaRoot: 3n, gigaEdgeIndex: 4n },
                { proofExpireTimeStamp: 7n, historicTimeStamp: 8n },
                9n,
                10n,
                unshielding,
                nullifiers,
                recipients,
                d.gigaIndex,
            ]);
            const asBigInt = inputs.map((x) => BigInt(x));

            // 9 head fields, then 3 per unshielding slot, then nullifiers, then recipient commitments.
            // the giga index range moved into the assetId, only current_giga_index is left and the contract fills it in.
            // `PubInputs` in circuits/src/main.nr puts public_hash (passed through) before first_message_hash (the
            // contract hashes it from the first two messages), so the proof only verifies with them in that order
            const head = 9;
            assert.equal(asBigInt.length, head + CIRCUIT_SIZE * 5);
            assert.deepEqual(asBigInt.slice(0, head), [1n, 2n, 3n, 4n, d.gigaIndex, 7n, 8n, 10n, 9n]);
            assert.deepEqual(asBigInt.slice(head + 3, head + 6), [0x11n, 0x12n, 0x13n]);
            assert.equal(asBigInt[head + CIRCUIT_SIZE * 3 + 2], 0x22n);
            assert.equal(asBigInt[head + CIRCUIT_SIZE * 4 + 3], 0x33n);
        });

        it("rejects arrays that are not CIRCUIT_SIZE long", async () => {
            const tx = validTx();
            tx.nullifiers = [0n];
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /WrongCircuitSize/);
        });

        it("rejects a root the tree never had", async () => {
            const tx = validTx();
            tx.roots.localRoot = root + 1n;
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /UnknownLocalRoot/);
        });

        it("rejects an edge index that does not match the root's tree size", async () => {
            const tx = validTx();
            tx.roots.localEdgeIndex = 1n;
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /WrongLocalEdgeIndex/);
        });

        it("rejects a giga root until the giga tree is plugged in, 0 means local only", async () => {
            const tx = validTx();
            tx.roots.gigaRoot = 1n;
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /UnknownGigaRoot/);
        });

        it("rejects an expired proof", async () => {
            const tx = validTx();
            tx.timeStamps.proofExpireTimeStamp = now - 1n;
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /ProofExpired/);
        });

        it("rejects a historic timestamp in the future", async () => {
            const tx = validTx();
            tx.timeStamps.historicTimeStamp = now + 1_000_000n;
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /HistoricTimeStampInFuture/);
        });

        it("rejects a nullifier that was already spent", async () => {
            const tx = validTx();
            tx.nullifiers = [1n, 1n, 2n, 3n];
            await assert.rejects(d.warptoad.write.transactPrivate([tx]), /NullifierAlreadySpent/);
        });

        it("reaches the verifier once everything else checks out", async () => {
            // a garbage proof is as far as this suite gets: the verifier itself must be the thing that rejects
            await assert.rejects(
                d.warptoad.write.transactPrivate([validTx()]),
                (err: Error) =>
                    !/WrongCircuitSize|UnknownLocalRoot|WrongLocalEdgeIndex|UnknownGigaRoot|ProofExpired|HistoricTimeStampInFuture|NullifierAlreadySpent/.test(
                        String(err),
                    ),
            );
        });
    });
});
