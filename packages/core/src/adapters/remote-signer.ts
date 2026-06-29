import { type Address, type Hex, type LocalAccount, type TypedDataDefinition } from "viem";
import { toAccount } from "viem/accounts";

export type RemoteSignTypedData = (params: TypedDataDefinition) => Promise<Hex>;

/**
 * Serialize a viem TypedDataDefinition into the standard `eth_signTypedData_v4`
 * JSON string (EIP712Domain prepended, bigints stringified). Providers like
 * Circle take this JSON form rather than a structured object.
 */
export function eip712ToJson(params: TypedDataDefinition): string {
  const domain = (params.domain ?? {}) as Record<string, unknown>;
  const domainTypes: Array<{ name: string; type: string }> = [];
  if (domain.name !== undefined) domainTypes.push({ name: "name", type: "string" });
  if (domain.version !== undefined) domainTypes.push({ name: "version", type: "string" });
  if (domain.chainId !== undefined) domainTypes.push({ name: "chainId", type: "uint256" });
  if (domain.verifyingContract !== undefined)
    domainTypes.push({ name: "verifyingContract", type: "address" });
  if (domain.salt !== undefined) domainTypes.push({ name: "salt", type: "bytes32" });

  const payload = {
    types: { EIP712Domain: domainTypes, ...params.types },
    domain,
    primaryType: params.primaryType,
    message: params.message,
  };
  return JSON.stringify(payload, (_key, value) =>
    typeof value === "bigint" ? value.toString() : value,
  );
}

/**
 * Wrap a provider's typed-data signing (Circle, Privy, any MPC/server wallet)
 * into a viem LocalAccount usable as an @x402/evm ClientEvmSigner.
 *
 * Only signTypedData is supported — that's all the EIP-3009 / Permit2 payment
 * paths need. signMessage / signTransaction throw, since these wallets sign
 * payment authorizations, not arbitrary messages or raw transactions.
 */
export function createRemoteSignerAccount(
  address: Address,
  signTypedData: RemoteSignTypedData,
): LocalAccount {
  return toAccount({
    address,
    async signTypedData(params): Promise<Hex> {
      return signTypedData(params as TypedDataDefinition);
    },
    async signMessage(): Promise<Hex> {
      throw new Error(
        "remote signer supports only signTypedData (used by EIP-3009 / Permit2)",
      );
    },
    async signTransaction(): Promise<Hex> {
      throw new Error("remote signer does not sign raw transactions");
    },
  }) as LocalAccount;
}
