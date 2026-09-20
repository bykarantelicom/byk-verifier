/* The six public Hardhat/Anvil development accounts used by the rc6 conformance vectors. Their private keys
 * are published all over the internet: a stream that names one of them as data signer or governance member is
 * worthless, so every place that accepts a signer or governance address refuses them. */
import { type Bytes, toHex } from "./bytes";

export const PUBLIC_TEST_ADDRESSES: ReadonlySet<string> = new Set([
  "f39fd6e51aad88f6f4ce6ab8827279cfffb92266", "70997970c51812dc3a010c7d01b50e0d17dc79c8", "3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
  "90f79bf6eb2c4f870365e785982e1f101e93b906", "15d34aaf54267db7d7c367839aaf71a00a2c6a65", "9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
]);

export function assertNotPublicTestAddress(address: Bytes): void {
  if (PUBLIC_TEST_ADDRESSES.has(toHex(address))) throw new Error("refusing a public test key: this address belongs to a published development account");
}
