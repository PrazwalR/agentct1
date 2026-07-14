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

export interface CircleAdapterConfig {
  /** CIRCLE_API_KEY — falls back to env. */
  apiKey?: string;
  /** CIRCLE_ENTITY_SECRET — falls back to env. */
  entitySecret?: string;
  /** Developer-controlled wallet id to sign with. */
  walletId: string;
  /** The wallet's EVM address. */
  address: Address;
  chain?: string;
  rpcUrl?: string;
}

/**
 * Circle developer-controlled (MPC) wallet adapter. The agent never holds a raw
 * key — Circle signs EIP-712 typed data server-side. We wrap Circle's
 * signTypedData into a viem LocalAccount via the remote-signer bridge.
 *
 * NOTE: typed against @circle-fin/developer-controlled-wallets but not exercised
 * against a live Circle account here — requires CIRCLE_API_KEY + entity secret.
 */
export class CircleAdapter implements IWalletAdapter {
  readonly provider = "circle";
  readonly chain: string;
  private signer?: LocalAccount;
  private readonly nonces = new InFlightNonceTracker();

  constructor(private readonly cfg: CircleAdapterConfig) {
    this.chain = cfg.chain ?? "eip155:84532";
  }

  private async ensureSigner(): Promise<LocalAccount> {
    if (this.signer) return this.signer;
    const apiKey = this.cfg.apiKey ?? process.env.CIRCLE_API_KEY;
    const entitySecret = this.cfg.entitySecret ?? process.env.CIRCLE_ENTITY_SECRET;
    if (!apiKey) throw new Error("CircleAdapter: CIRCLE_API_KEY not set (config.apiKey or env)");
    if (!entitySecret) {
      throw new Error("CircleAdapter: CIRCLE_ENTITY_SECRET not set (config.entitySecret or env)");
    }
    const { initiateDeveloperControlledWalletsClient } =
      await import("@circle-fin/developer-controlled-wallets");
    const client = initiateDeveloperControlledWalletsClient({ apiKey, entitySecret });
    this.signer = createRemoteSignerAccount(this.cfg.address, async (params) => {
      const res = await client.signTypedData({
        walletId: this.cfg.walletId,
        data: eip712ToJson(params),
      });
      const sig = res.data?.signature;
      if (!sig) throw new Error("Circle signTypedData returned no signature");
      return sig as Hex;
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
