import type { Address, Hex, LocalAccount } from "viem";
import type {
  IWalletAdapter,
  PaymentRequest,
  SignedAuthorization,
  SignedPermit2Authorization,
} from "../types.js";
import { InFlightNonceTracker, signEIP3009Authorization } from "../x402/eip3009.js";
import { signPermit2Authorization } from "../x402/permit2.js";
import { erc20Balance, makePublicClient } from "./base.js";
import { createRemoteSignerAccount, eip712ToJson } from "./remote-signer.js";

export interface PrivyAdapterConfig {
  /** PRIVY_APP_ID — falls back to env. */
  appId?: string;
  /** PRIVY_APP_SECRET — falls back to env. */
  appSecret?: string;
  /** Privy wallet id to sign with. */
  walletId: string;
  /** The wallet's EVM address. */
  address: Address;
  chain?: string;
  rpcUrl?: string;
}

/**
 * Privy (MPC) server-wallet adapter. Privy signs EIP-712 typed data via its
 * wallet API; we wrap that into a viem LocalAccount via the remote-signer bridge.
 *
 * NOTE: typed against @privy-io/server-auth but not exercised against a live
 * Privy app here — requires PRIVY_APP_ID + PRIVY_APP_SECRET.
 */
export class PrivyAdapter implements IWalletAdapter {
  readonly provider = "privy";
  readonly chain: string;
  private signer?: LocalAccount;
  private readonly nonces = new InFlightNonceTracker();

  constructor(private readonly cfg: PrivyAdapterConfig) {
    this.chain = cfg.chain ?? "eip155:84532";
  }

  private async ensureSigner(): Promise<LocalAccount> {
    if (this.signer) return this.signer;
    const appId = this.cfg.appId ?? process.env.PRIVY_APP_ID;
    const appSecret = this.cfg.appSecret ?? process.env.PRIVY_APP_SECRET;
    if (!appId) throw new Error("PrivyAdapter: PRIVY_APP_ID not set (config.appId or env)");
    if (!appSecret)
      throw new Error("PrivyAdapter: PRIVY_APP_SECRET not set (config.appSecret or env)");
    const { PrivyClient } = await import("@privy-io/server-auth");
    const privy = new PrivyClient(appId, appSecret);
    this.signer = createRemoteSignerAccount(this.cfg.address, async (params) => {
      const res = await privy.walletApi.ethereum.signTypedData({
        walletId: this.cfg.walletId,
        // Serialize bigints (message value/validAfter/validBefore, Permit2 amount/
        // nonce/deadline) to strings — Privy's SDK JSON-serializes the payload and
        // would otherwise throw "Do not know how to serialize a BigInt".
        typedData: JSON.parse(eip712ToJson(params)) as never,
      });
      return res.signature as Hex;
    });
    return this.signer;
  }

  async getAddress(): Promise<Address> {
    return this.cfg.address;
  }

  async getSigner(): Promise<LocalAccount> {
    return this.ensureSigner();
  }

  async getBalance(token: Address): Promise<bigint> {
    return erc20Balance(makePublicClient(this.chain, this.cfg.rpcUrl), token, this.cfg.address);
  }

  async authorizePayment(req: PaymentRequest): Promise<SignedAuthorization> {
    return signEIP3009Authorization(req, await this.ensureSigner(), { tracker: this.nonces });
  }

  async authorizePaymentPermit2(req: PaymentRequest): Promise<SignedPermit2Authorization> {
    return signPermit2Authorization(req, await this.ensureSigner());
  }

  /** Release an EIP-3009 nonce once its authorization has settled or expired. */
  releaseNonce(nonce: Hex): void {
    this.nonces.release(nonce);
  }
}
