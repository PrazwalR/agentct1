import { randomUUID } from "node:crypto";
import type { PaymentRequest, PolicyDecision } from "./types.js";

export interface PendingApproval {
  id: string;
  request: PaymentRequest;
  decision: PolicyDecision;
  createdAt: number;
  expiresAt: number;
}

export interface ApprovalQueueOptions {
  /** How long a pending approval waits before auto-denying (default 300s). */
  defaultTimeoutSeconds?: number;
}

interface QueueSlot {
  item: PendingApproval;
  resolve: (approved: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * In-process human-in-the-loop queue for escalated payments. Use its `enqueue`
 * as the guard's onEscalation: an escalated payment parks here and the promise
 * resolves only when a human resolve()s it (approve/deny) — or the timeout denies
 * it. An operator's service lists() pending items and calls resolve() from an
 * approval UI / endpoint.
 */
export class ApprovalQueue {
  private readonly pending = new Map<string, QueueSlot>();

  constructor(private readonly opts: ApprovalQueueOptions = {}) {}

  /** Park an escalated payment. Resolves true (approved) or false (denied/timeout). */
  enqueue(
    request: PaymentRequest,
    decision: PolicyDecision,
    timeoutSeconds?: number,
  ): Promise<boolean> {
    const id = randomUUID();
    const timeoutMs = (timeoutSeconds ?? this.opts.defaultTimeoutSeconds ?? 300) * 1000;
    const now = Date.now();
    const item: PendingApproval = {
      id,
      request,
      decision,
      createdAt: now,
      expiresAt: now + timeoutMs,
    };

    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(false);
      }, timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
      this.pending.set(id, { item, resolve, timer });
    });
  }

  /** All currently-pending approvals (oldest first). */
  list(): PendingApproval[] {
    return [...this.pending.values()].map((s) => s.item).sort((a, b) => a.createdAt - b.createdAt);
  }

  get(id: string): PendingApproval | undefined {
    return this.pending.get(id)?.item;
  }

  /** Approve or deny a pending payment. Returns false if the id isn't pending. */
  resolve(id: string, approved: boolean): boolean {
    const slot = this.pending.get(id);
    if (!slot) return false;
    clearTimeout(slot.timer);
    this.pending.delete(id);
    slot.resolve(approved);
    return true;
  }

  get size(): number {
    return this.pending.size;
  }
}
