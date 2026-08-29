import assert from "node:assert/strict";
import { before, beforeEach, describe, it } from "node:test";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WarptoadContract } from "../src/types.js";
import { chainName, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";
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

/** poseidon2_bn254(1, 2), the placeholder commitment `shieldErc20` currently inserts. */
const POSEIDON2_OF_1_AND_2 =
    0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383n;

describe("Warptoad", async function () {
    const { viem } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [deployer, other] = await viem.getWalletClients();

    let chainLabels: { symbol: string; name: string };
    let warptoad: WarptoadContract;
    let blocked: ContractReturnType<"MockERC20">;
    let gigaIndex: bigint;
    let skinnyIMT: any;

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

            // The placeholder commitment: whatever the etched Yul contract at POSEIDON2_YUL
            // returns for hash_2(1, 2). Asserting the vector rather than trusting the etch means
            // stale or wrong bytecode in node_modules fails here instead of passing silently.
            const leaves = await warptoad.read.getSkinnyLeaves([treeId, 0n, 1n]);
            assert.deepEqual(leaves, [POSEIDON2_OF_1_AND_2]);
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
    });
});
