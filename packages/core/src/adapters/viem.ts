import type { Address, Hex, LocalAccount } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  IWalletAdapter,
  PaymentRequest,
  SignedAuthorization,
  SignedPermit2Authorization,
} from "../types.js";
import { signEIP3009Authorization } from "../x402/eip3009.js";
import { signPermit2Authorization } from "../x402/permit2.js";
import { erc20Balance, makePublicClient } from "./base.js";

export interface ViemAdapterConfig {
  /** Local private key. DEV ONLY — never use a real funded mainnet key. */
  privateKey: Hex;
  /** CAIP-2 chain, default Base Sepolia. */
  chain?: string;
  rpcUrl?: string;
}

/**
 * Raw viem wallet adapter backed by a local private key.
 * The simplest signer for development and tests; the account doubles directly
 * as an @x402/evm ClientEvmSigner.
 */
export class ViemAdapter implements IWalletAdapter {
  readonly provider = "viem";
  readonly chain: string;
  private readonly account: LocalAccount;
  private readonly rpcUrl?: string;

  constructor(cfg: ViemAdapterConfig) {
    this.account = privateKeyToAccount(cfg.privateKey);
    this.chain = cfg.chain ?? "eip155:84532";
    this.rpcUrl = cfg.rpcUrl;
  }

  async getAddress(): Promise<Address> {
    return this.account.address;
  }

  async getSigner(): Promise<LocalAccount> {
    return this.account;
  }

  async getBalance(token: Address): Promise<bigint> {
    return erc20Balance(makePublicClient(this.chain, this.rpcUrl), token, this.account.address);
  }

  async authorizePayment(req: PaymentRequest): Promise<SignedAuthorization> {
    return signEIP3009Authorization(req, this.account);
  }

  async authorizePaymentPermit2(req: PaymentRequest): Promise<SignedPermit2Authorization> {
    return signPermit2Authorization(req, this.account);
  }
}
