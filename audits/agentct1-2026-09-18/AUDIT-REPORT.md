# Security Audit — agentctl `AuditAnchor`

**Scope**: `contracts/src/AuditAnchor.sol`, `contracts/script/Deploy.s.sol`, and the off-chain
code that produces and consumes its data (`packages/core/src/audit/*`, `packages/cli/src/cli.ts`).
**Commit**: working tree at `85cfa9f` + uncommitted gap-closing changes.
**Target chain**: Base Sepolia today, Base mainnet intended (OP Stack).
**Date**: 2026-09-18
**Method**: 5 parallel specialist agents (`general`, `precision-math`, `dos`, `access-control`,
`chain-specific`) against the evm-audit-skills checklists. 42 raw findings deduplicated to 26.

---

## Executive summary

**The Solidity is not where the risk is.** `AuditAnchor.sol` is 61 lines, holds no funds, has no
external calls, no assembly, no proxy, and no arithmetic. Its Merkle verification was compiled and
replayed against real `@openzeppelin/merkle-tree@1.0.8` vectors and is **byte-compatible with
OpenZeppelin** — unsigned `LT` ordering, 64-byte `abi.encodePacked`, and correct proof indexing
despite `sortLeaves: true`. Nine of nine vector tests passed, including two fuzz properties.

The risk is that **the contract is too stateless to carry the guarantee the product sells**, and
that the off-chain glue around it has several outright bugs. The README claims the anchor "proves
a log entry wasn't altered after commitment." What it actually proves is narrower:

> An entry the operator still chooses to show you hashes into a root the operator still chose to
> publish — for the subset of that entry's fields that happen to be in the leaf preimage.

Three independent gaps each break that claim on their own: batches are **not chained** (H-3),
the **settlement outcome is not in the leaf** (H-2), and **only the audited party can verify**
(M-3).

### Remediation status (as of this working tree)

**26 findings: 21 fixed, 3 documented/accepted, 2 won't-fix.**

| Finding                                | Status                                                                                                                                                                                 |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| H-1 batch-index race                   | **Fixed** — index parsed from the `BatchCommitted` receipt log; contract also returns it                                                                                               |
| H-2 settlement outside the leaf        | **Fixed** — `hashEntry` now covers `settlement` and `resourceUrl`                                                                                                                      |
| H-3 equivocation / no chaining         | **Fixed** — `commitBatch` requires the caller to name the current head, so each operator has one unforkable chain; the verifier cross-checks committed entry counts to detect deletion |
| H-4 unsafe-head finality               | **Fixed** — commits wait for the `safe` tag before tagging rows, plus `reconcile()` releases batches whose root is absent on chain                                                     |
| H-5 hot committer EOA                  | **Documented + partly mitigated** — separate `ANCHOR_DEPLOYER_KEY`, trust model written up in the README. Out-of-process signing is an operational change, not a code one              |
| M-1 leaf/node domain separation        | **Fixed** — `verifyEntry` takes entry fields and computes the double-keccak leaf itself; no pre-hashed leaf is accepted                                                                |
| M-2 `entryCount` unchecked             | **Fixed** — verifier compares per-batch and whole-chain committed counts against the local log                                                                                         |
| M-3 verification needs the private key | **Fixed** — `--operator <address>`                                                                                                                                                     |
| M-4 hardcoded Sepolia RPC              | **Fixed** — RPC selected per chain, plus an `assertChainId()` backstop                                                                                                                 |
| M-5 no chain/anchor/operator binding   | **Fixed** — all three are leaf fields, recomputed by the contract                                                                                                                      |
| M-6 sequencer-attested timestamp       | **Documented** — README trust-model section states what the timestamp does and does not prove                                                                                          |
| M-7 zero root accepted                 | **Fixed** — `EmptyRoot` / `EmptyBatch` reverts                                                                                                                                         |
| M-8 `--verify` is O(N²)                | **Fixed** — `proofsForBatch` builds each batch tree once                                                                                                                               |
| M-9 non-atomic commit→tag              | **Fixed** — durable-tag wait plus `reconcile()`; commit timeout raised to 15 min                                                                                                       |
| M-10 `Panic(0x32)` aborts the run      | **Fixed** — reads return `found: false` instead of reverting, and the CLI handles per-batch failures                                                                                   |
| L-1 unbounded proof loop               | **Fixed** — `MAX_PROOF_LENGTH = 64`                                                                                                                                                    |
| L-2 permissionless state growth        | **Won't fix** — confirmed not griefable (arrays are `msg.sender`-keyed); a diffuse L2 state cost with no victim                                                                        |
| L-3 forced-inclusion aliasing          | **Documented** — affects only a contract (Safe) operator; EOA operators are unaffected                                                                                                 |
| L-4 leaf timestamp unbounded           | **Fixed** — verifier rejects an entry postdating its batch                                                                                                                             |
| L-5 unpinned evm_version/pragma        | **Fixed** — `evm_version = "cancun"`, `pragma solidity 0.8.24`                                                                                                                         |
| L-6 deployer/operator conflated        | **Fixed** — separate deployer key, script prints the distinction                                                                                                                       |
| L-7 2s timestamp granularity           | **Won't fix** — inherent to the chain; covered by the trust-model docs                                                                                                                 |
| I-1 struct packing                     | **Fixed** — `Batch` packed to 2 slots (`uint64` timestamp + entryCount, validated)                                                                                                     |
| I-2, I-3, I-4                          | No action needed — verified non-issues                                                                                                                                                 |

**⚠ Breaking change.** The contract and the leaf format both changed, so this requires a
**fresh deployment and a re-anchor**; roots committed by the previous version cannot be
verified by this one (by design — the leaf now binds chain, anchor and operator). Nothing
was deployed to mainnet, so no migration path is needed.

GitHub issues #1–#5 (`PrazwalR/agentct1`) cover H-1…H-5 and are ready to close once committed.

### Severity counts### Severity counts

| Severity | Count |
| -------- | ----- |
| Critical | 0     |
| High     | 5     |
| Medium   | 10    |
| Low      | 7     |
| Info     | 4     |

### Strongest signal

**Five of five agents independently flagged the same bug** from five different checklists: the
batch index is derived by a racy read-after-write (`H-1`). When it is wrong, honestly-anchored
entries become permanently unprovable, and the CLI reports it identically to real tampering. The
correct index is already emitted as an indexed event topic and already present in a receipt the
client awaits and discards. It is a handful of lines to fix and should be fixed first.

---

## High

### [H-1] Batch index derived by a racy read-after-write; wrong values are permanent and unrecoverable

**Severity**: High · **Merged from**: D-1, AC-5, CS-3, G-4, PM-7 (all five agents)
**Location**: `packages/core/src/audit/logger.ts:121`, `packages/core/src/audit/anchor.ts:64-89`, `AuditAnchor.sol:34`

`commitBatch` returns nothing, so `flush()` infers its own index:

```ts
const txHash = await this.anchorClient.commit(root, rows.length); // awaits the receipt
const operator = this.anchorClient.operatorAddress();
const idx = (await this.anchorClient.getBatchCount(operator)) - 1; // ...then re-reads
```

`commit()` **awaits `waitForTransactionReceipt` and then discards the receipt**, returning only
`txHash`. That receipt contains the `BatchCommitted` log, whose `batchIndex` is an indexed topic —
the exact value being guessed. (The event is not even present in `AUDIT_ANCHOR_ABI`.)

Three ways the inference goes wrong:

- **Concurrency**: two flushes sharing `ANCHOR_COMMITTER_KEY` both read the same count and both tag
  the same `idx`. This is not hypothetical — `audit/store.ts` ships Postgres explicitly "for
  multi-agent operators", and there is exactly one committer-key env var.
- **Read consistency**: `getBatchCount` hits a fresh `PublicClient` against load-balanced RPCs; a
  lagging replica returns a stale count.
- **Reorg**: see H-4.

Because `proofFor()` rebuilds the tree from **locally tagged** rows, a wrong tag means the rebuilt
root never matches the on-chain root. `verifyEntry` returns false forever; the contract is
append-only with no owner, so there is no repair path. `agentctl audit --verify` prints
`✗ MISMATCH` — indistinguishable from genuine tampering.

**Recommendation** (client-side, no redeploy needed): add `BatchCommitted` to `AUDIT_ANCHOR_ABI`,
return the receipt from `commit()`, and `parseEventLogs` the authoritative index. Additionally, have
`commitBatch` return `uint256 batchIndex` in any future deployment.

---

### [H-2] The settlement outcome is outside the leaf preimage and can be rewritten after anchoring

**Severity**: High · **Merged from**: G-6
**Location**: `packages/core/src/audit/logger.ts:19-31`, `packages/core/src/audit/merkle.ts:22-30`

`hashEntry` commits to `{intent, amount, token, recipient, chain, agentId, verdict, riskScore,
checks}`. `entryToLeaf` builds `[agentId, timestamp, recipient, verdictNum, entryHash]`.

`AuditEntry.settlement` — `{txHash, nonce, facilitator, success}`, i.e. **whether the payment
actually executed and its on-chain transaction hash** — is persisted to `settlement_json` and never
enters the tree. So is `resourceUrl`.

An attacker with **only database write access and no committer key** can `UPDATE audit_entries SET
settlement_json = ...` on a months-old anchored entry. The recomputed root is bit-identical,
`verifyEntry` returns true, and `--verify` prints `✓ verified on-chain` over the falsified record.
Mutating `request` or `decision` _is_ caught — so tamper-evidence holds for the policy decision and
fails for the payment outcome, which is the half an auditor actually cares about.

**Recommendation**: include a hash of the settlement (and `resourceUrl`) in the leaf preimage. Note
this is a leaf-format change — batch it with any other change to `LEAF_TYPES` (see M-5).

---

### [H-3] Batches are unordered and unlinked — an operator can equivocate and rewrite anchored history undetectably

**Severity**: High · **Merged from**: AC-2, G-3
**Location**: `AuditAnchor.sol:34-39`, `packages/cli/src/cli.ts:482-495`

Nothing binds batch _N_ to batch _N-1_: no `prevRoot`, no sequence number in the leaf, no rule that
a later root extends an earlier one. On chain an observer sees only a list of unrelated 32-byte
values. The contradiction between two conflicting histories is **unprovable even in principle**.

`verifyEntries()` reads `batchIndex` from the operator's own SQLite row, rebuilds the tree from
`entriesInBatch(batchIndex)` — also operator-controlled — and compares against a root the operator
freely chose to publish. Every input except the on-chain root is attacker-chosen.

**Proof of concept**:

```sql
DELETE FROM audit_entries WHERE id='e3';
-- commitBatch(R1, 4)
UPDATE audit_entries SET batch_index=1 WHERE batch_index=0;
```

`--verify` then prints `✓ verified on-chain` for every surviving entry with zero warnings. The
deleted entry is never reported missing because **the loop only iterates rows that still exist** —
there is no completeness check anywhere in the path.

**Recommendation**: chain the batches — `require(prevRoot == head[msg.sender])` with `head` updated
on commit — and make the verifier enumerate `BatchCommitted` logs from chain rather than trusting
the local `batch_index` column. Both are required; either alone is insufficient.

---

### [H-4] A commit is treated as final at the unsafe head; an L2 reorg silently un-anchors entries with no retry path

**Severity**: High · **Merged from**: CS-2
**Location**: `packages/core/src/audit/anchor.ts:85`, `packages/core/src/audit/store.ts:146`

`waitForTransactionReceipt` uses viem's default `confirmations: 1`, which on OP Stack returns at the
**unsafe head**. Only `safe`/`finalized` are irreversible. `flush()` then immediately calls
`markBatched()`, stamping `batch_index` locally.

If the unsafe head reorgs, the commit disappears — but `unbatched()` selects
`WHERE batch_index IS NULL`, and those rows are no longer NULL. **No code path ever re-anchors
them.** The loss is permanent and silent. `AnchorConfig.intervalMs` is declared and never read, so
nothing retries or repairs.

**Recommendation**: wait for `safe` (or `finalized`) before `markBatched`, and add a reconciliation
pass that re-checks anchored batches against chain and clears `batch_index` when a root is absent.

---

### [H-5] Operator identity is a single hot EOA, co-located with the policy engine, with no rotation or revocation

**Severity**: High · **Merged from**: AC-1
**Location**: `packages/core/src/audit/logger.ts:62-72`, `contracts/script/Deploy.s.sol:14`

The operator is an address and nothing more. There is no registry, no rotation, no revocation, and
the contract is immutable — so a compromised or lost committer key cannot be repudiated or replaced,
and every past anchor stays attributed to it.

This is what makes H-3 reachable by a **host attacker** rather than only a dishonest operator:
`AuditLogger` holds `committerKey` in the same process that evaluates payment policy, so a single
host compromise yields both the SQLite log and the anchoring authority — exactly the two capabilities
the rewrite requires. `Deploy.s.sol` reads the same env var, so the secret also lives in CI.

**Recommendation**: separate the committer key from the policy-engine process (a signing service or
a dedicated key), and record a canonical operator identity with a rotation path. At minimum,
document that compromise of `ANCHOR_COMMITTER_KEY` invalidates the guarantee retroactively.

---

## Medium

### [M-1] No leaf/internal-node domain separation — internal nodes and the root itself verify as entries

**Severity**: Medium · **Merged from**: PM-1, G-1
**Location**: `AuditAnchor.sol:42-56`

`verifyEntry` takes an opaque pre-hashed `bytes32` leaf, sets `computed = leaf`, and compares to the
root. It cannot distinguish a leaf from an internal node. Confirmed passing against a genuine 8-leaf
root: `verifyEntry(op, i, root, [])` returns `true`, and internal node `n01` with proof `[n23]`
returns `true`.

The system is saved only by OZ's `standardLeafHash` being a **double** keccak while internal nodes
are single — an invariant of one client library that the contract neither enforces nor documents.
The shipped CLI is safe (it derives the leaf itself and cross-checks `rootMatch`), but the NatSpec's
"anyone can later verify" does not hold for an independent third-party verifier, which is the entire
point of anchoring. `testVerifySingleLeaf` encodes the legitimate 1-leaf case, so the test suite
cannot distinguish the two.

**Recommendation**: have `verifyEntry` accept the entry fields and compute
`keccak256(bytes.concat(keccak256(abi.encode(...))))` itself, rather than trusting a caller-supplied
leaf.

### [M-2] `entryCount` is unauthenticated, unbound to the root, and discarded by the verifier

**Severity**: Medium · **Merged from**: AC-4, PM-3, D-8
**Location**: `AuditAnchor.sol:34`, `packages/cli/src/cli.ts:488-491`

The only completeness signal in the system is a self-attested `uint256` with no cryptographic tie to
the tree. Worse, the one available cross-check is dropped: `cli.ts:488` fetches
`{root, timestamp, entryCount}` and line 491 uses only `root`. A repo-wide grep confirms `entryCount`
is never compared to anything. `Number(entryCount)` at `anchor.ts:137` also silently loses precision
above 2^53.

**Recommendation**: at minimum compare `entryCount` to the rebuilt leaf count and fail loudly on
mismatch. Better, commit the count inside the tree.

### [M-3] Verification requires the committer private key — only the audited party can verify

**Severity**: Medium · **Merged from**: AC-3
**Location**: `packages/cli/src/cli.ts:469-480`

`audit --verify` refuses to run without `ANCHOR_COMMITTER_KEY` and derives the operator address from
it via `anchor.operatorAddress()`. Verification needs only a _public_ address. As written, separation
of duties collapses: the only party who can check the log is the party being audited.

**Recommendation**: add `--operator <address>` and require the key only for `commit`.

### [M-4] CLI verification hardcodes the Base Sepolia RPC regardless of `--chain`

**Severity**: Medium · **Merged from**: CS-5
**Location**: `packages/cli/src/cli.ts:477`

`chain` flows from `--chain`, but `rpcUrl` is unconditionally `process.env.RPC_BASE_SEPOLIA`.
`makePublicClient` pairs Base **mainnet**'s chain object with a **Sepolia** transport, and viem does
not validate chain id on plain reads — so `audit --verify --chain eip155:8453` prints
`verified on-chain` from testnet data. It only bites when `RPC_BASE_SEPOLIA` is set, which is
precisely the setup `.env.example` instructs.

**Recommendation**: select the RPC by chain, and assert `publicClient.getChainId()` matches.

### [M-5] No chain, contract, or operator domain separation in the leaf or root

**Severity**: Medium · **Merged from**: CS-4
**Location**: `packages/core/src/audit/merkle.ts:12`

`LEAF_TYPES` carries no chain id, anchor address, or operator. A Base Sepolia anchor is byte-identical
to a Base mainnet one, and the store persists only an integer `batch_index`. Anyone can replay a
published root under their own address on another chain and claim authorship.

**Recommendation**: bind chain id + anchor address + operator into the leaf preimage. Batch with H-2.

### [M-6] `block.timestamp` is a single-sequencer attestation, not an attested clock

**Severity**: Medium · **Merged from**: CS-1
**Location**: `AuditAnchor.sol:36`

The product's core claim is "this root existed at this time," and that timestamp is set by Coinbase's
sequencer, bounded only by `max_sequencer_drift = 1800s` forward and by outage catch-up backward.
Timestamps step in exact 2s increments, so after an outage they lag wall clock.

**Recommendation**: document that the anchor's time is L2-sequencer-attested, not wall-clock proof.
For a stronger claim, anchor to L1 or include an external timestamp attestation.

### [M-7] A zero root makes `bytes32(0)` an unconditionally valid entry, forever

**Severity**: Medium · **Merged from**: G-2, AC-6, PM-2
**Location**: `AuditAnchor.sol:34`, `packages/core/src/audit/merkle.ts:16`

`commitBatch` validates nothing. After a `bytes32(0)` commit, `verifyEntry(op, i, bytes32(0), [])`
returns true permanently, and batches are append-only and uncorrectable. Reachable by construction:
`MerkleAuditBatch.root()` returns `ZERO_ROOT` by design for an empty batch. `flush()` currently
guards `rows.length === 0`, but `root()` is exported public API.

**Recommendation**: `require(merkleRoot != bytes32(0))` and `require(entryCount > 0)`.

### [M-8] `audit --verify` is O(N^2) and has no error handling

**Severity**: Medium · **Merged from**: D-3, D-4
**Location**: `packages/cli/src/cli.ts:481-496`, `packages/core/src/audit/logger.ts:125-144`

`flush()` imposes no batch size cap and `proofFor()` rebuilds the full batch tree **per entry**
inside the CLI's per-entry loop. At N=50,000 that is ~2.5e9 leaf hashes. Separately, the loop makes
2 serial, uncached, unguarded RPC calls per entry with no `try/catch`, so one 429 from the default
public `https://sepolia.base.org` discards every already-confirmed result. The on-chain side is not
the bottleneck — proofs are log2(N).

**Recommendation**: build the batch tree once per batch, cache `getBatch`, and wrap per-entry
verification so one failure doesn't abort the run.

### [M-9] Non-atomic commit-then-tag with a 180s receipt timeout orphans roots

**Severity**: Medium · **Merged from**: D-2
**Location**: `packages/core/src/audit/anchor.ts:85`

`waitForTransactionReceipt` is called with no overrides (viem default `timeout = 180_000`). On a
slow-mining tx it throws _after_ the root is committed but _before_ `markBatched`, so rows stay
unbatched, the next flush builds a different tree, and the first root is permanently orphaned. This
is self-perpetuating under congestion.

**Recommendation**: persist the pending commit before broadcasting and reconcile on restart.

### [M-10] `Panic(0x32)` on an out-of-range index aborts the entire verification run

**Severity**: Medium · **Merged from**: D-6, AC-7, CS-8, G-5
**Location**: `AuditAnchor.sol:48`, `packages/cli/src/cli.ts:482-496`

`batches[operator][batchIndex]` reverts rather than returning false, including for an operator with
zero batches. Since `operator` is derived from whatever key is in the env at verify time, a rotated
key or redeployed contract makes the **first** call panic and kills the whole run with an opaque
error — the same signal as a tampered log.

**Recommendation**: bounds-check and return `false`; add `try/catch` in the CLI loop.

---

## Low

| ID  | Finding                                                                                                                                                                                                                                                               | Source    |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| L-1 | Unbounded `proof.length` loop in `verifyEntry` — `view`-only and gas-capped today, but the bound is inherited by any future on-chain integrator and cannot be added later                                                                                             | D-5, PM-2 |
| L-2 | `commitBatch` is permissionless and unmetered — a pure state-growth externality (~66k gas/commit, no refund path). Confirmed _not_ griefable: the array is `msg.sender`-keyed, so no attacker can grow a victim's array, shift indices, or invalidate an issued proof | D-7       |
| L-3 | Forced inclusion via `OptimismPortal` works for an EOA operator but is silently broken by L1-to-L2 address aliasing for a Safe/contract operator — the batch lands under the aliased address                                                                          | CS-6      |
| L-4 | Leaf `timestamp` is operator-supplied `Date.now()`, never compared to `Batch.timestamp` — the anchor bounds entry age from above only                                                                                                                                 | G-7       |
| L-5 | `evm_version` unpinned (floats with Foundry, currently `cancun`; solc 0.8.24's own default is `shanghai`) and a floating `^0.8.24` pragma against a pinned toolchain                                                                                                  | CS-9, G-8 |
| L-6 | `Deploy.s.sol` conflates deployer with operator; no canonical operator recorded on chain                                                                                                                                                                              | AC-8      |
| L-7 | 2-second timestamp granularity makes same-block batch timestamps non-distinguishing and non-ordering                                                                                                                                                                  | CS-7      |

## Info

| ID  | Finding                                                                                                                                                                                                             | Source           |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| I-1 | `Batch` uses 3 storage slots where 2 suffice — **21,752 gas/commit measured**. Caveat: `uint64(block.timestamp)` is safe, `uint64(entryCount)` is **not** without SafeCast while `entryCount` stays caller-supplied | PM-4, G-8, CS-10 |
| I-2 | `batches[msg.sender].length - 1` **cannot** underflow — `push` precedes the `emit` with no external call between. Under 0.8.x it would revert `Panic(0x11)`, not wrap. Do not add `unchecked`                       | PM-5             |
| I-3 | Loop counter cannot overflow; `unchecked` is provably safe but worth only ~178 gas on a `view` function                                                                                                             | PM-6             |
| I-4 | Absence of owner/pause/upgrade is **correct** for this contract — the missing governance belongs at the identity layer (H-5), not here                                                                              | AC-9             |

---

## Explicitly cleared

Not findings; recorded so the next audit does not re-derive them.

- **OZ byte-compatibility**: leaf hash, node hash, ordering, proof walk, and concatenation all match
  `@openzeppelin/merkle-tree@1.0.8`. Verified by executing real vectors against the compiled contract
  (9/9, incl. 2 fuzz properties at 256 runs).
- **`bytes32 <` is unsigned `LT`**, identical to the JS lib's `BigInt` compare and OZ
  `Hashes.commutativeKeccak256` — proven with a test that signed comparison would fail.
- **`abi.encodePacked(bytes32,bytes32)`** is exactly 64 unambiguous bytes. Collision hazard requires
  two _variable-length_ operands; not reachable here.
- **`getProof(i)` indexing** is correct despite `sortLeaves: true` — `indexedValues` stays in
  insertion order with `treeIndex` into the sorted tree. Confirmed for n = 1,2,3,5,8,9.
- **Odd-node duplication forgery**: not possible — OZ `makeMerkleTree` uses a proper `2n-1` array
  with no trailing-node padding.
- **PUSH0 / Cancun opcodes**: deployed bytecode disassembled — `PUSH0 x31, TIMESTAMP x1` only. No
  MCOPY/TSTORE/TLOAD/BLOBHASH/SELFDESTRUCT. PUSH0 live on Base since Canyon (Jan 2024).
- **Cross-operator writes**: impossible — `commitBatch` takes no `operator` argument.
- **Vacuous by construction**: all reentrancy variants, external-call handling, returndata bombing,
  gas forwarding, try/catch, force-feeding ETH, `msg.value`/multicall, pause/oracle/token-behavior
  items, ERC20/721/4626/4337 items, proxies, signatures, flash loans, and governance — the contract
  makes no external calls, holds no value, and has no admin surface.

---

## Recommended order of work

1. ~~**H-1**~~ — **done**. Index now comes from the commit's own event.
2. **H-4** + **M-9** — same subsystem as H-1; fix the anchoring lifecycle in one pass. **Next.**
3. ~~**M-3**, **M-4**~~ — **done**. **M-10** client half done; contract half pending a redeploy.
4. **H-2** + **M-5** — one leaf-format change; do them together, they both touch `LEAF_TYPES`.
5. **H-3** — needs a contract change (`prevRoot` chaining) plus a verifier that reads chain, not
   local state. Largest change; schedule deliberately.
6. **M-1**, **M-7** — contract changes; batch with H-3 into a single redeploy.
7. **H-5** — operational/key-management, not code.

Since the contract is immutable and not yet deployed to mainnet, **items 5 and 6 should land before
any mainnet deployment.**

## Documentation correction

README "Honest limitations" #4 currently reads: _"It proves a log entry wasn't altered after
commitment."_ Given H-2 and H-3, the accurate statement is that it proves an entry the operator
shows you is consistent with a root the operator points you at, for the fields inside the leaf
preimage. That should be corrected regardless of which fixes land.
