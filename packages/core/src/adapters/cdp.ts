import type { Address, Hex, LocalAccount } from "viem";
import { toAccount } from "viem/accounts";
import type {
  IWalletAdapter,
  PaymentRequest,
  SignedAuthorization,
  SignedPermit2Authorization,
} from "../types.js";
import { InFlightNonceTracker, signEIP3009Authorization } from "../x402/eip3009.js";
import { signPermit2Authorization } from "../x402/permit2.js";
import { erc20Balance, makePublicClient } from "./base.js";

export interface CdpAdapterConfig {
  /** CDP_API_KEY_ID — falls back to env. */
  apiKeyId?: string;
  /** CDP_API_KEY_SECRET — falls back to env. */
  apiKeySecret?: string;
  /** CDP_WALLET_SECRET — falls back to env. */
  walletSecret?: string;
  /** Named CDP server account to get-or-create. */
  accountName?: string;
  /** CAIP-2 chain, default Base Sepolia. */
  chain?: string;
  rpcUrl?: string;
}

/**
 * Coinbase CDP server-wallet adapter.
 *
 * CDP holds the keys (server-controlled, TEE-secured); agentctl never sees a
 * raw private key. The CDP EvmServerAccount exposes a viem-compatible
 * signTypedData, so `toAccount()` turns it into a LocalAccount that doubles as
 * the @x402/evm ClientEvmSigner — the choke point the x402 client signs through.
 */
export class CdpAdapter implements IWalletAdapter {
  readonly provider = "cdp";
  readonly chain: string;
  private readonly cfg: CdpAdapterConfig;
  private signer?: LocalAccount;
  private readonly nonces = new InFlightNonceTracker();

  constructor(cfg: CdpAdapterConfig = {}) {
    this.cfg = cfg;
    this.chain = cfg.chain ?? "eip155:84532";
  }

  /** Lazily authenticate to CDP and resolve the server account once. */
  private async ensureSigner(): Promise<LocalAccount> {
    if (this.signer) return this.signer;
    // Lazy import: consumers using only the viem adapter need not install CDP creds.
    const { CdpClient } = await import("@coinbase/cdp-sdk");
    const cdp = new CdpClient({
      apiKeyId: this.cfg.apiKeyId ?? process.env.CDP_API_KEY_ID,
      apiKeySecret: this.cfg.apiKeySecret ?? process.env.CDP_API_KEY_SECRET,
      walletSecret: this.cfg.walletSecret ?? process.env.CDP_WALLET_SECRET,
    });
    const account = await cdp.evm.getOrCreateAccount({
      name: this.cfg.accountName ?? process.env.CDP_ACCOUNT_NAME ?? "agentctl-agent",
    });
    // CDP EvmServerAccount satisfies viem's CustomSource (address + sign* methods),
    // but its types don't line up nominally — bridge through toAccount.
    this.signer = toAccount(
      account as unknown as Parameters<typeof toAccount>[0],
    ) as unknown as LocalAccount;
    return this.signer;
  }

  async getAddress(): Promise<Address> {
    return (await this.ensureSigner()).address;
  }

  async getSigner(): Promise<LocalAccount> {
    return this.ensureSigner();
  }

  async getBalance(token: Address): Promise<bigint> {
    return erc20Balance(
      makePublicClient(this.chain, this.cfg.rpcUrl),
      token,
      await this.getAddress(),
    );
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
