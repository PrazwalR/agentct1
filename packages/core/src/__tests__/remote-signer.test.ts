import { describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { parseUnits, verifyTypedData, type Address } from "viem";
import { createRemoteSignerAccount, eip712ToJson } from "../adapters/remote-signer.js";
import { TRANSFER_WITH_AUTHORIZATION_TYPES, signEIP3009Authorization } from "../x402/eip3009.js";
import { getChain } from "../constants.js";
import type { PaymentRequest } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const DEAD = "0x000000000000000000000000000000000000dEaD" as Address;

describe("remote signer account", () => {
  it("produces valid, recoverable EIP-3009 signatures via a delegated signer", async () => {
    // Stand in for a Circle/Privy MPC wallet using a local key behind the delegate.
    const backing = privateKeyToAccount(generatePrivateKey());
    let calls = 0;
    const remote = createRemoteSignerAccount(backing.address, async (params) => {
      calls++;
      return backing.signTypedData(params);
    });

    const req: PaymentRequest = {
      intent: "t",
      amount: parseUnits("0.10", 6),
      token: USDC,
      recipient: DEAD,
      chain: "eip155:84532",
      agentId: "a",
    };
    const signed = await signEIP3009Authorization(req, remote);
    expect(calls).toBe(1);

    const valid = await verifyTypedData({
      address: backing.address,
      domain: getChain("eip155:84532").usdcDomain,
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: signed.authorization,
      signature: signed.signature,
    });
    expect(valid).toBe(true);
  });

  it("rejects signMessage / signTransaction", async () => {
    const backing = privateKeyToAccount(generatePrivateKey());
    const remote = createRemoteSignerAccount(backing.address, async () => "0x00");
    await expect(remote.signMessage({ message: "hi" })).rejects.toThrow(/signTypedData/);
  });

  it("serializes typed data to eth_signTypedData_v4 JSON (Circle/provider form)", async () => {
    const req: PaymentRequest = {
      intent: "t",
      amount: parseUnits("0.10", 6),
      token: USDC,
      recipient: DEAD,
      chain: "eip155:84532",
      agentId: "a",
    };
    let capturedJson = "";
    const backing = privateKeyToAccount(generatePrivateKey());
    const remote = createRemoteSignerAccount(backing.address, async (params) => {
      capturedJson = eip712ToJson(params);
      return backing.signTypedData(params);
    });
    await signEIP3009Authorization(req, remote);

    const parsed = JSON.parse(capturedJson);
    expect(parsed.types.EIP712Domain).toBeDefined();
    expect(parsed.primaryType).toBe("TransferWithAuthorization");
    // bigints are serialized as decimal strings
    expect(parsed.message.value).toBe("100000");
    expect(typeof parsed.domain.chainId).toBe("number");
  });
});
