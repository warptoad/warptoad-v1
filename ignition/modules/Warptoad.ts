import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("Warptoad", (m) => {
  const warptoad = m.contract("Warptoad");

  //m.call(warptoad, "incBy", [5n]);

  return { warptoad };
});
