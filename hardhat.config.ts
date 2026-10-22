import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";
import { configVariable, defineConfig, task } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatToolboxViemPlugin],
  tasks: [
    task("verify-wrapper", "Verify a wrapper token that Warptoad deployed, constructor args are read from chain")
      .addPositionalArgument({ name: "wrapper", description: "Address of the WarptoadERC20 or WarptoadERC1155" })
      .setAction(() => import("./scripts/verifyWrapper.js"))
      .build(),
  ],
  solidity: {
    profiles: {
      // Warptoad embeds the creation code of both wrapper tokens, which puts it
      // over the 24576-byte limit unoptimized. The optimizer is on here too so
      // dev and test builds deploy the same way a production one does.
      default: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
      production: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    hardhatOp: {
      type: "edr-simulated",
      chainType: "op",
    },
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      // deployer first: ignition and relaying use it. Alice and bob are separate EOAs so the live test runs read
      // as three parties on etherscan, the tests top them up with gas from the deployer
      accounts: [
        configVariable("SEPOLIA_PRIVATE_KEY"),
        configVariable("SEPOLIA_ALICE_PRIVATE_KEY"),
        configVariable("SEPOLIA_BOB_PRIVATE_KEY"),
      ],
    },
  },
  verify: {
    etherscan: {
      // one key covers every chain on the Etherscan v2 api
      apiKey: configVariable("ETHERSCAN_API_KEY"),
    },
  },
});
