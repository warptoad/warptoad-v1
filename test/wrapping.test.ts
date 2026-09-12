import assert from "node:assert/strict";
import { before, beforeEach, describe, it } from "node:test";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WarptoadContract } from "../src/types.js";
import { chainName, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";
import { CIRCUIT_SIZE } from "../src/constants.js";
import { hashCommitment } from "../src/hashing.js";
import { deployCreate2, type Create2Artifact, deployCreate2Factory } from "@warptoad/skinny-fat-imt-js/create2"

import { type Hex } from "viem";
import skinnyIMTArtifact from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/SkinnyIMTPoseidon2WriteStorage" with { type: "json" };
import IMTSalts from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/create2-salts.json" with { type: "json" };
import poseidon2YulArtifact from "poseidon2-evm/out/Poseidon2Yul.sol/Poseidon2Yul_BN254.json" with { type: "json" };

/**
 * The address `poseidon2-evm`'s `Poseidon2` library hardcodes for its Yul contract.
 * Same on every chain zemse has deployed it to.
 */
const POSEIDON2_YUL = "0xB2542195Ad96AcfBC962C48A97D7640A9F5386D2" as const;

describe("Warptoad", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, other] = await viem.getWalletClients();

    let chainLabels: { symbol: string; name: string };
    let warptoad: WarptoadContract;
    let blocked: ContractReturnType<"MockERC20">;
    let gigaIndex: bigint;
    let skinnyIMT: any;
    let verifier: ContractReturnType<"WarptoadVerifier">;

    before(async () => {
        await deployCreate2Factory(publicClient, deployer, deployer.account);
        skinnyIMT = await deployCreate2({
            artifact: skinnyIMTArtifact as Create2Artifact,
            salt: IMTSalts.SkinnyIMTPoseidon2WriteStorage[0] as Hex,
            walletClient: deployer,
            publicClient: publicClient,
        })

        // `Poseidon2.YUL` is a hardcoded address and poseidon2-evm publishes no CREATE2 salt, so
        // unlike the IMT library above it cannot be redeployed to that address locally. Etching the
        // shipped runtime bytecode is the only way to reach it from a fresh node.
        // @TODO open an issue at github.com/zemse/poseidon2-evm asking for the deployment salt to be
        // published, so this can become a real deployCreate2 like the IMT library above.
        const testClient = await viem.getTestClient();
        await testClient.setCode({
            address: POSEIDON2_YUL,
            bytecode: poseidon2YulArtifact.deployedBytecode.object as Hex,
        });

        chainLabels = chainName(await publicClient.getChainId());
        // we used to use chainIds to define what chain a commitment can be spend on
        // but that has issues when a rollup or L1 forks since then everyone has assets on both forks
        // but not for warptoad users
        // also contract needs to know it's index anyway!
        gigaIndex = BigInt(0n)

        // generated from the circuit by `pnpm noir`
        verifier = await viem.deployContract("WarptoadVerifier");
    });

    beforeEach(async () => {
        // Stands in for a rebasing token: something the deployer knows breaks the 1:1
        // invariant and blocks deposits on from the start.
        blocked = await viem.deployContract("MockERC20", ["Rebasing", "REB", 18]);
        warptoad = await viem.deployContract(
            "Warptoad",
            [
                SYMBOL_PREFIX,
                NAME_PREFIX,
                chainLabels.symbol,
                chainLabels.name,
                gigaIndex,
                verifier.address,
                BigInt(CIRCUIT_SIZE),
                0n, // gigaFirstValidIndex
                0n, // gigaLastValidIndex
                [blocked.address],
            ],
            {
                libraries: {
                    SkinnyIMTPoseidon2WriteStorage: skinnyIMT.address
                }
            }
        );
    });

    describe("blocklist", () => {
        it("marks the constructor's tokens closed and leaves everything else open", async () => {
            const token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            assert.equal(await warptoad.read.closedPools([blocked.address]), true);
            assert.equal(await warptoad.read.closedPools([token.address]), false);
        });

        it("refuses deposits of a blocked token", async () => {
            await blocked.write.mint([deployer.account.address, 1000n]);
            await blocked.write.approve([warptoad.address, 1000n]);

            await assert.rejects(
                warptoad.write.wrapERC20([blocked.address, 1000n, deployer.account.address]),
                /PoolIsClosed/,
            );
            // No wrapper should have been deployed for it either.
            assert.equal(
                await warptoad.read.erc20WrapperOf([blocked.address]),
                "0x0000000000000000000000000000000000000000",
            );
        });

        it("refuses ERC-1155 deposits of a blocked collection", async () => {
            const collection = await viem.deployContract("MockERC1155", ["Blocked", "BLK", "ipfs://x/"]);
            const vault = await viem.deployContract(
                "Warptoad",
                [
                    SYMBOL_PREFIX,
                    NAME_PREFIX,
                    chainLabels.symbol,
                    chainLabels.name,
                    gigaIndex,
                    verifier.address,
                    BigInt(CIRCUIT_SIZE),
                    0n,
                    0n,
                    [collection.address],
                ],
                {
                    libraries: {
                        SkinnyIMTPoseidon2WriteStorage: skinnyIMT.address
                    }
                }
            );;
            await collection.write.mint([deployer.account.address, 1n, 5n]);
            await collection.write.setApprovalForAll([vault.address, true]);

            await assert.rejects(
                vault.write.wrapERC1155([collection.address, 1n, 5n, deployer.account.address]),
                /PoolIsClosed/,
            );
        });
    });

    describe("wrapERC20", () => {
        let token: ContractReturnType<"MockERC20">;

        beforeEach(async () => {
            token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            await token.write.mint([deployer.account.address, 1_000_000n]);
            await token.write.approve([warptoad.address, 1_000_000n]);
        });

        it("names the wrapper from the naming functions", async () => {
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);

            const wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
            const wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);

            assert.equal(await wrapper.read.symbol(), `${SYMBOL_PREFIX}USDC@${chainLabels.symbol}`);
            assert.equal(
                await wrapper.read.name(),
                `Wrapped ${NAME_PREFIX} USD Coin ${chainLabels.name}`,
            );
        });

        it("mirrors the underlying's decimals", async () => {
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);

            const wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
            const wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);

            assert.equal(await wrapper.read.decimals(), 6);
            // viem checksums addresses it decodes but not ones it returns from a deploy.
            assert.equal(
                (await wrapper.read.underlying()).toLowerCase(),
                token.address.toLowerCase(),
            );
        });


        it("mints 1:1 and vaults the collateral", async () => {
            await warptoad.write.wrapERC20([token.address, 1000n, other.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC20",
                await warptoad.read.erc20WrapperOf([token.address]),
            );
            assert.equal(await wrapper.read.balanceOf([other.account.address]), 1000n);
            assert.equal(await wrapper.read.totalSupply(), 1000n);
            assert.equal(await token.read.balanceOf([warptoad.address]), 1000n);
        });

        it("reuses the wrapper on subsequent wraps", async () => {
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);
            const first = await warptoad.read.erc20WrapperOf([token.address]);

            await warptoad.write.wrapERC20([token.address, 500n, deployer.account.address]);
            assert.equal(await warptoad.read.erc20WrapperOf([token.address]), first);

            const wrapper = await viem.getContractAt("WarptoadERC20", first);
            assert.equal(await wrapper.read.totalSupply(), 1500n);
        });

        it("mints only what a fee-on-transfer token actually delivers", async () => {
            await token.write.setFeeBps([100n]); // 1%
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC20",
                await warptoad.read.erc20WrapperOf([token.address]),
            );
            assert.equal(await wrapper.read.totalSupply(), 990n);
            assert.equal(await token.read.balanceOf([warptoad.address]), 990n);
        });


        it("reads legacy bytes32 metadata", async () => {
            const legacy = await viem.deployContract("MockBytes32MetadataERC20");
            await legacy.write.mint([deployer.account.address, 1000n]);
            await legacy.write.approve([warptoad.address, 1000n]);

            await warptoad.write.wrapERC20([legacy.address, 1000n, deployer.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC20",
                await warptoad.read.erc20WrapperOf([legacy.address]),
            );
            assert.equal(await wrapper.read.symbol(), `${SYMBOL_PREFIX}LGCY@${chainLabels.symbol}`);
            assert.equal(
                await wrapper.read.name(),
                `Wrapped ${NAME_PREFIX} Legacy Token ${chainLabels.name}`,
            );
        });

        it("falls back to the address when a token exposes no metadata", async () => {
            const bare = await viem.deployContract("MockNoMetadataERC20");
            await bare.write.mint([deployer.account.address, 1000n]);
            await bare.write.approve([warptoad.address, 1000n]);

            await warptoad.write.wrapERC20([bare.address, 1000n, deployer.account.address]);

            const wrapperAddress = await warptoad.read.erc20WrapperOf([bare.address]);
            const wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);
            assert.equal(
                (await wrapper.read.symbol()).toLowerCase(),
                `${SYMBOL_PREFIX}${bare.address}@${chainLabels.symbol}`.toLowerCase(),
            );
            // No readable decimals() means the conventional 18.
            assert.equal(await wrapper.read.decimals(), 18);
        });

        it("keeps both levels straight when a wrapper is itself wrapped", async () => {
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);
            const inner = await warptoad.read.erc20WrapperOf([token.address]);
            const innerToken = await viem.getContractAt("WarptoadERC20", inner);

            await innerToken.write.approve([warptoad.address, 500n]);
            await warptoad.write.wrapERC20([inner, 500n, deployer.account.address]);
            const outer = await warptoad.read.erc20WrapperOf([inner]);

            // Each level redeems for its own underlying; neither registry entry clobbers the other.
            assert.equal((await warptoad.read.underlyingOf([outer]))[0], inner);
            assert.equal((await warptoad.read.underlyingOf([inner]))[0].toLowerCase(), token.address.toLowerCase());

            await warptoad.write.unwrapERC20([outer, 500n, deployer.account.address]);
            assert.equal(await innerToken.read.balanceOf([deployer.account.address]), 1000n);
        });
    });

    describe("unwrapERC20", () => {
        let token: ContractReturnType<"MockERC20">;
        let wrapper: ContractReturnType<"WarptoadERC20">;
        let wrapperAddress: `0x${string}`;

        beforeEach(async () => {
            token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            await token.write.mint([deployer.account.address, 1000n]);
            await token.write.approve([warptoad.address, 1000n]);
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);
            wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
            wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);
        });

        it("burns the wrapper and releases the collateral", async () => {
            await warptoad.write.unwrapERC20([wrapperAddress, 400n, other.account.address]);

            assert.equal(await wrapper.read.balanceOf([deployer.account.address]), 600n);
            assert.equal(await wrapper.read.totalSupply(), 600n);
            assert.equal(await token.read.balanceOf([other.account.address]), 400n);
            assert.equal(await token.read.balanceOf([warptoad.address]), 600n);
        });

        it("round-trips the full balance with nothing left over", async () => {
            await warptoad.write.unwrapERC20([wrapperAddress, 1000n, deployer.account.address]);

            assert.equal(await wrapper.read.totalSupply(), 0n);
            assert.equal(await token.read.balanceOf([warptoad.address]), 0n);
            assert.equal(await token.read.balanceOf([deployer.account.address]), 1000n);
        });




        it("rejects a token this vault did not issue", async () => {
            await assert.rejects(
                warptoad.write.unwrapERC20([token.address, 1n, deployer.account.address]),
                /NotAWrapper/,
            );
        });

        it("rejects unwrapping an ERC-1155 wrapper through the ERC-20 path", async () => {
            const collection = await viem.deployContract("MockERC1155", ["Toads", "TOAD", "ipfs://toads/"]);
            await collection.write.mint([deployer.account.address, 1n, 5n]);
            await collection.write.setApprovalForAll([warptoad.address, true]);
            await warptoad.write.wrapERC1155([collection.address, 1n, 5n, deployer.account.address]);

            const erc1155Wrapper = await warptoad.read.erc1155WrapperOf([collection.address]);
            await assert.rejects(
                warptoad.write.unwrapERC20([erc1155Wrapper, 1n, deployer.account.address]),
                /NotAWrapper/,
            );
        });

        it("lets only the vault mint or burn the wrapper", async () => {
            await assert.rejects(wrapper.write.mint([deployer.account.address, 1n]), /OnlyWarptoad/);
            await assert.rejects(wrapper.write.burn([deployer.account.address, 1n]), /OnlyWarptoad/);
        });
    });

    describe("shieldErc20", () => {
        let token: ContractReturnType<"MockERC20">;
        let wrapperAddress: `0x${string}`;
        let treeId: bigint;

        beforeEach(async () => {
            token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            await token.write.mint([deployer.account.address, 1000n]);
            await token.write.approve([warptoad.address, 1000n]);
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);
            wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
            // Derived from a storage slot at init, so ask the contract rather than hardcode it.
            treeId = await warptoad.read.commitmentTreeId();
        });

        it("burns the wrapper and inserts the commitment as a leaf", async () => {
            await warptoad.write.shieldErc20([wrapperAddress, 400n, 42n]);

            const wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);
            assert.equal(await wrapper.read.balanceOf([deployer.account.address]), 600n);

            // Computed with the js Poseidon2 (same one the circuit uses), so this also pins the
            // etched Yul contract at POSEIDON2_YUL to the circuit's hash_3.
            const assetId = await warptoad.read.assetId([token.address, 0n, gigaIndex, 0]);
            const commitment = hashCommitment({ preCommitmentHash: 42n, assetId, amount: 400n });
            const leaves = await warptoad.read.getSkinnyLeaves([treeId, 0n, 1n]);
            assert.deepEqual(leaves, [commitment]);
        });

        it("records every root with the tree size at that time", async () => {
            await warptoad.write.shieldErc20([wrapperAddress, 400n, 42n]);
            const root = await warptoad.read.getSkinnyRoot([treeId]);
            assert.equal(await warptoad.read.localRoots([root]), 1n);
            assert.equal(await warptoad.read.localRoots([root + 1n]), 0n);
        });

        it("rejects a token this vault did not issue", async () => {
            await assert.rejects(
                warptoad.write.shieldErc20([token.address, 1n, 42n]),
                /NotAWrapper/,
            );
        });
    });

    describe("ERC-1155", () => {
        let collection: ContractReturnType<"MockERC1155">;

        beforeEach(async () => {
            collection = await viem.deployContract("MockERC1155", ["Toads", "TOAD", "ipfs://toads/{id}"]);
            await collection.write.mint([deployer.account.address, 7n, 10n]);
            await collection.write.setApprovalForAll([warptoad.address, true]);
        });

        it("names the wrapper collection from the naming functions", async () => {
            await warptoad.write.wrapERC1155([collection.address, 7n, 4n, deployer.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC1155",
                await warptoad.read.erc1155WrapperOf([collection.address]),
            );
            assert.equal(await wrapper.read.symbol(), `${SYMBOL_PREFIX}TOAD@${chainLabels.symbol}`);
            assert.equal(await wrapper.read.name(), `Wrapped ${NAME_PREFIX} Toads ${chainLabels.name}`);
        });

        it("mints the same id 1:1 and vaults the collateral", async () => {
            await warptoad.write.wrapERC1155([collection.address, 7n, 4n, other.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC1155",
                await warptoad.read.erc1155WrapperOf([collection.address]),
            );
            assert.equal(await wrapper.read.balanceOf([other.account.address, 7n]), 4n);
            assert.equal(await collection.read.balanceOf([warptoad.address, 7n]), 4n);
            assert.equal(await collection.read.balanceOf([deployer.account.address, 7n]), 6n);
        });

        it("forwards uri() to the underlying collection", async () => {
            await warptoad.write.wrapERC1155([collection.address, 7n, 4n, deployer.account.address]);

            const wrapper = await viem.getContractAt(
                "WarptoadERC1155",
                await warptoad.read.erc1155WrapperOf([collection.address]),
            );
            assert.equal(await wrapper.read.uri([7n]), await collection.read.uri([7n]));
        });

        it("round-trips through unwrapERC1155", async () => {
            await warptoad.write.wrapERC1155([collection.address, 7n, 4n, deployer.account.address]);
            const wrapperAddress = await warptoad.read.erc1155WrapperOf([collection.address]);

            await warptoad.write.unwrapERC1155([wrapperAddress, 7n, 4n, deployer.account.address]);

            const wrapper = await viem.getContractAt("WarptoadERC1155", wrapperAddress);
            assert.equal(await wrapper.read.balanceOf([deployer.account.address, 7n]), 0n);
            assert.equal(await collection.read.balanceOf([deployer.account.address, 7n]), 10n);
            assert.equal(await collection.read.balanceOf([warptoad.address, 7n]), 0n);
        });

        it("shields an id and inserts the commitment as a leaf", async () => {
            await warptoad.write.wrapERC1155([collection.address, 7n, 4n, deployer.account.address]);
            const wrapperAddress = await warptoad.read.erc1155WrapperOf([collection.address]);
            const wrapper = await viem.getContractAt("WarptoadERC1155", wrapperAddress);

            await warptoad.write.shieldErc1155([wrapperAddress, 7n, 3n, 42n]);

            assert.equal(await wrapper.read.balanceOf([deployer.account.address, 7n]), 1n);
            // AssetType.ERC1155 == 2, id goes in the slot ERC-20 leaves at 0
            const assetId = await warptoad.read.assetId([collection.address, 7n, gigaIndex, 2]);
            const commitment = hashCommitment({ preCommitmentHash: 42n, assetId, amount: 3n });
            const treeId = await warptoad.read.commitmentTreeId();
            assert.deepEqual(await warptoad.read.getSkinnyLeaves([treeId, 0n, 1n]), [commitment]);
        });
    });
    describe("verifyShieldedTx", () => {
        let token: ContractReturnType<"MockERC20">;
        let wrapperAddress: `0x${string}`;
        let root: bigint;
        let now: bigint;

        const zeros = () => new Array<bigint>(CIRCUIT_SIZE).fill(0n);
        const noUnshield = () =>
            new Array(CIRCUIT_SIZE).fill(null).map(() => ({ recipient: 0n, amount: 0n, assetId: 0n }));
        const noTargets = () =>
            new Array(CIRCUIT_SIZE).fill(null).map(() => ({
                wrapper: "0x0000000000000000000000000000000000000000" as `0x${string}`,
                id: 0n,
            }));

        /** everything valid except the proof, so each test breaks one thing */
        const validTx = () => ({
            roots: {
                localRoot: root,
                localEdgeIndex: 0n,
                gigaRoot: 0n,
                gigaEdgeIndex: 0n,
            },
            timeStamps: { proofExpireTimeStamp: now + 3600n, historicTimeStamp: now - 3600n },
            unshieldingCommitments: noUnshield(),
            unshieldTargets: noTargets(),
            // nullifiers get stored before anything else is checked, so they have to be distinct
            nullifiers: [1n, 2n, 3n, 4n],
            recipientCommitmentsHashes: zeros(),
            proof: "0x" as `0x${string}`,
        });

        beforeEach(async () => {
            token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
            await token.write.mint([deployer.account.address, 1000n]);
            await token.write.approve([warptoad.address, 1000n]);
            await warptoad.write.wrapERC20([token.address, 1000n, deployer.account.address]);
            wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
            await warptoad.write.shieldErc20([wrapperAddress, 400n, 42n]);
            root = await warptoad.read.getSkinnyRoot([await warptoad.read.commitmentTreeId()]);
            now = (await publicClient.getBlock()).timestamp;
        });

        it("lays out the public inputs in the circuit's order", async () => {
            const unshielding = noUnshield();
            unshielding[1] = { recipient: 0x11n, amount: 0x12n, assetId: 0x13n };
            const nullifiers = zeros();
            nullifiers[2] = 0x22n;
            const recipients = zeros();
            recipients[3] = 0x33n;

            const inputs = await warptoad.read.formatPublicInputs([
                { localRoot: 1n, localEdgeIndex: 2n, gigaRoot: 3n, gigaEdgeIndex: 4n },
                { proofExpireTimeStamp: 7n, historicTimeStamp: 8n },
                9n,
                unshielding,
                nullifiers,
                recipients,
            ]);
            const asBigInt = inputs.map((x) => BigInt(x));

            // 10 head fields, then 3 per unshielding slot, then nullifiers, then recipient commitments.
            // giga valid index range (0, 0 here) and current giga index come from the contract, not calldata
            assert.equal(asBigInt.length, 10 + CIRCUIT_SIZE * 5);
            assert.deepEqual(asBigInt.slice(0, 10), [1n, 2n, 3n, 4n, 0n, 0n, gigaIndex, 7n, 8n, 9n]);
            assert.deepEqual(asBigInt.slice(10 + 3, 10 + 6), [0x11n, 0x12n, 0x13n]);
            assert.equal(asBigInt[10 + CIRCUIT_SIZE * 3 + 2], 0x22n);
            assert.equal(asBigInt[10 + CIRCUIT_SIZE * 4 + 3], 0x33n);
        });

        it("rejects arrays that are not CIRCUIT_SIZE long", async () => {
            const tx = validTx();
            tx.nullifiers = [0n];
            await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /WrongCircuitSize/);
        });

        it("rejects a root the tree never had", async () => {
            const tx = validTx();
            tx.roots.localRoot = root + 1n;
            await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /UnknownLocalRoot/);
        });

        it("rejects an edge index that does not match the root's tree size", async () => {
            const tx = validTx();
            tx.roots.localEdgeIndex = 1n;
            await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /WrongLocalEdgeIndex/);
        });

        it("rejects an expired proof", async () => {
            const tx = validTx();
            tx.timeStamps.proofExpireTimeStamp = now - 1n;
            await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /ProofExpired/);
        });

        it("rejects a historic timestamp in the future", async () => {
            const tx = validTx();
            tx.timeStamps.historicTimeStamp = now + 1_000_000n;
            await assert.rejects(warptoad.write.verifyShieldedTx([tx]), /HistoricTimeStampInFuture/);
        });

        it("reaches the verifier once everything else checks out", async () => {
            // no prover in this test suite yet, so a garbage proof is as far as we get:
            // the verifier itself must be the thing that rejects
            await assert.rejects(
                warptoad.write.verifyShieldedTx([validTx()]),
                (err: Error) =>
                    !/WrongCircuitSize|UnknownLocalRoot|WrongLocalEdgeIndex|ProofExpired|HistoricTimeStampInFuture|NullifierAlreadySpent/
                        .test(String(err)),
            );
        });
    });
});
