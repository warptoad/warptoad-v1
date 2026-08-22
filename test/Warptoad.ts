import assert from "node:assert/strict";
import { before, beforeEach, describe, it } from "node:test";
import { network } from "hardhat";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WarptoadContract } from "../src/types.js";
import { chainName, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";

describe("Warptoad", async function () {
  const { viem } = await network.create();
  const publicClient = await viem.getPublicClient();
  const [holder, other] = await viem.getWalletClients();

  let chainLabels: { symbol: string; name: string };
  let warptoad: WarptoadContract;

  before(async () => {
    chainLabels = chainName(await publicClient.getChainId());
  });

  beforeEach(async () => {
    warptoad = await viem.deployContract("Warptoad", [
      SYMBOL_PREFIX,
      NAME_PREFIX,
      chainLabels.symbol,
      chainLabels.name,
    ]);
  });

  describe("wrapERC20", () => {
    let token: ContractReturnType<"MockERC20">;

    beforeEach(async () => {
      token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
      await token.write.mint([holder.account.address, 1_000_000n]);
      await token.write.approve([warptoad.address, 1_000_000n]);
    });

    it("names the wrapper from the naming functions", async () => {
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);

      const wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
      const wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);

      assert.equal(await wrapper.read.symbol(), `${SYMBOL_PREFIX}USDC@${chainLabels.symbol}`);
      assert.equal(
        await wrapper.read.name(),
        `Wrapped ${NAME_PREFIX} USD Coin ${chainLabels.name}`,
      );
    });

    it("mirrors the underlying's decimals", async () => {
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);

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
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);
      const first = await warptoad.read.erc20WrapperOf([token.address]);

      await warptoad.write.wrapERC20([token.address, 500n, holder.account.address]);
      assert.equal(await warptoad.read.erc20WrapperOf([token.address]), first);

      const wrapper = await viem.getContractAt("WarptoadERC20", first);
      assert.equal(await wrapper.read.totalSupply(), 1500n);
    });

    it("mints only what a fee-on-transfer token actually delivers", async () => {
      await token.write.setFeeBps([100n]); // 1%
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);

      const wrapper = await viem.getContractAt(
        "WarptoadERC20",
        await warptoad.read.erc20WrapperOf([token.address]),
      );
      assert.equal(await wrapper.read.totalSupply(), 990n);
      assert.equal(await token.read.balanceOf([warptoad.address]), 990n);
    });


    it("reads legacy bytes32 metadata", async () => {
      const legacy = await viem.deployContract("MockBytes32MetadataERC20");
      await legacy.write.mint([holder.account.address, 1000n]);
      await legacy.write.approve([warptoad.address, 1000n]);

      await warptoad.write.wrapERC20([legacy.address, 1000n, holder.account.address]);

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
      await bare.write.mint([holder.account.address, 1000n]);
      await bare.write.approve([warptoad.address, 1000n]);

      await warptoad.write.wrapERC20([bare.address, 1000n, holder.account.address]);

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
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);
      const inner = await warptoad.read.erc20WrapperOf([token.address]);
      const innerToken = await viem.getContractAt("WarptoadERC20", inner);

      await innerToken.write.approve([warptoad.address, 500n]);
      await warptoad.write.wrapERC20([inner, 500n, holder.account.address]);
      const outer = await warptoad.read.erc20WrapperOf([inner]);

      // Each level redeems for its own underlying; neither registry entry clobbers the other.
      assert.equal(await warptoad.read.underlyingOf([outer]), inner);
      assert.equal((await warptoad.read.underlyingOf([inner])).toLowerCase(), token.address.toLowerCase());

      await warptoad.write.unwrapERC20([outer, 500n, holder.account.address]);
      assert.equal(await innerToken.read.balanceOf([holder.account.address]), 1000n);
    });
  });

  describe("unwrapERC20", () => {
    let token: ContractReturnType<"MockERC20">;
    let wrapper: ContractReturnType<"WarptoadERC20">;
    let wrapperAddress: `0x${string}`;

    beforeEach(async () => {
      token = await viem.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
      await token.write.mint([holder.account.address, 1000n]);
      await token.write.approve([warptoad.address, 1000n]);
      await warptoad.write.wrapERC20([token.address, 1000n, holder.account.address]);
      wrapperAddress = await warptoad.read.erc20WrapperOf([token.address]);
      wrapper = await viem.getContractAt("WarptoadERC20", wrapperAddress);
    });

    it("burns the wrapper and releases the collateral", async () => {
      await warptoad.write.unwrapERC20([wrapperAddress, 400n, other.account.address]);

      assert.equal(await wrapper.read.balanceOf([holder.account.address]), 600n);
      assert.equal(await wrapper.read.totalSupply(), 600n);
      assert.equal(await token.read.balanceOf([other.account.address]), 400n);
      assert.equal(await token.read.balanceOf([warptoad.address]), 600n);
    });

    it("round-trips the full balance with nothing left over", async () => {
      await warptoad.write.unwrapERC20([wrapperAddress, 1000n, holder.account.address]);

      assert.equal(await wrapper.read.totalSupply(), 0n);
      assert.equal(await token.read.balanceOf([warptoad.address]), 0n);
      assert.equal(await token.read.balanceOf([holder.account.address]), 1000n);
    });




    it("rejects a token this vault did not issue", async () => {
      await assert.rejects(
        warptoad.write.unwrapERC20([token.address, 1n, holder.account.address]),
        /NotAWrapper/,
      );
    });

    it("rejects unwrapping an ERC-1155 wrapper through the ERC-20 path", async () => {
      const collection = await viem.deployContract("MockERC1155", ["Toads", "TOAD", "ipfs://toads/"]);
      await collection.write.mint([holder.account.address, 1n, 5n]);
      await collection.write.setApprovalForAll([warptoad.address, true]);
      await warptoad.write.wrapERC1155([collection.address, 1n, 5n, holder.account.address]);

      const erc1155Wrapper = await warptoad.read.erc1155WrapperOf([collection.address]);
      await assert.rejects(
        warptoad.write.unwrapERC20([erc1155Wrapper, 1n, holder.account.address]),
        /NotAWrapper/,
      );
    });

    it("lets only the vault mint or burn the wrapper", async () => {
      await assert.rejects(wrapper.write.mint([holder.account.address, 1n]), /OnlyWarptoad/);
      await assert.rejects(wrapper.write.burn([holder.account.address, 1n]), /OnlyWarptoad/);
    });
  });

  describe("ERC-1155", () => {
    let collection: ContractReturnType<"MockERC1155">;

    beforeEach(async () => {
      collection = await viem.deployContract("MockERC1155", ["Toads", "TOAD", "ipfs://toads/{id}"]);
      await collection.write.mint([holder.account.address, 7n, 10n]);
      await collection.write.setApprovalForAll([warptoad.address, true]);
    });

    it("names the wrapper collection from the naming functions", async () => {
      await warptoad.write.wrapERC1155([collection.address, 7n, 4n, holder.account.address]);

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
      assert.equal(await collection.read.balanceOf([holder.account.address, 7n]), 6n);
    });

    it("forwards uri() to the underlying collection", async () => {
      await warptoad.write.wrapERC1155([collection.address, 7n, 4n, holder.account.address]);

      const wrapper = await viem.getContractAt(
        "WarptoadERC1155",
        await warptoad.read.erc1155WrapperOf([collection.address]),
      );
      assert.equal(await wrapper.read.uri([7n]), await collection.read.uri([7n]));
    });

    it("round-trips through unwrapERC1155", async () => {
      await warptoad.write.wrapERC1155([collection.address, 7n, 4n, holder.account.address]);
      const wrapperAddress = await warptoad.read.erc1155WrapperOf([collection.address]);

      await warptoad.write.unwrapERC1155([wrapperAddress, 7n, 4n, holder.account.address]);

      const wrapper = await viem.getContractAt("WarptoadERC1155", wrapperAddress);
      assert.equal(await wrapper.read.balanceOf([holder.account.address, 7n]), 0n);
      assert.equal(await collection.read.balanceOf([holder.account.address, 7n]), 10n);
      assert.equal(await collection.read.balanceOf([warptoad.address, 7n]), 0n);
    });
  });
});
