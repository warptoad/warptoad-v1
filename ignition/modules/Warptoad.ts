import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { NAME_PREFIX, SYMBOL_PREFIX } from "../../src/config.js";
import { CIRCUIT_SIZE } from "../../src/constants.js";
import skinnyIMTArtifact from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/SkinnyIMTPoseidon2WriteStorage" with { type: "json" };
import IMTSalts from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/create2-salts.json" with { type: "json" };

/**
 * Deploys WarptoadVerifier and Warptoad, linked against an already deployed SkinnyIMTPoseidon2WriteStorage.
 *
 * `chainSymbol` and `chainName` have no defaults on purpose: they end up as permanent token metadata, so a
 * deploy without a parameters file must fail rather than mislabel every wrapper. See src/config.ts and
 * ignition/parameters/<network>.json.
 *
 * The IMT library is a CREATE2 deployment, so it has the same address on every chain (see create2-salts.json).
 * The library is not compiled into this repo's artifacts, so its abi comes from the frozen create2 artifact.
 */
export default buildModule("Warptoad", (m) => {
    const chainSymbol = m.getParameter<string>("chainSymbol");
    const chainName = m.getParameter<string>("chainName");
    const gigaIndex = m.getParameter("gigaIndex", 0n);
    const gigaFirstValidIndex = m.getParameter("gigaFirstValidIndex", 0n);
    const gigaLastValidIndex = m.getParameter("gigaLastValidIndex", 0n);
    const blockedTokens = m.getParameter<string[]>("blockedTokens", []);
    const skinnyIMTAddress = m.getParameter<string>("skinnyIMT", IMTSalts.SkinnyIMTPoseidon2WriteStorage[1]);

    const skinnyIMT = m.contractAt(
        "SkinnyIMTPoseidon2WriteStorage",
        {
            _format: "hh3-artifact-1",
            contractName: skinnyIMTArtifact.contractName,
            sourceName: skinnyIMTArtifact.sourceName,
            abi: skinnyIMTArtifact.abi,
            bytecode: skinnyIMTArtifact.initCode,
            deployedBytecode: skinnyIMTArtifact.deployedBytecode,
            linkReferences: {},
            deployedLinkReferences: {},
        },
        skinnyIMTAddress,
    );

    const verifier = m.contract("WarptoadVerifier");

    const warptoad = m.contract(
        "Warptoad",
        [
            SYMBOL_PREFIX,
            NAME_PREFIX,
            chainSymbol,
            chainName,
            gigaIndex,
            verifier,
            BigInt(CIRCUIT_SIZE),
            gigaFirstValidIndex,
            gigaLastValidIndex,
            blockedTokens,
        ],
        { libraries: { SkinnyIMTPoseidon2WriteStorage: skinnyIMT } },
    );

    return { warptoad, verifier, skinnyIMT };
});
