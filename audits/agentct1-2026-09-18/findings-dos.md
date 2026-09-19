# DoS & Griefing — AuditAnchor.sol

**Domain**: `evm-audit-dos`
**Checklist**: https://github.com/austintgriffith/evm-audit-skills/blob/main/evm-audit-dos/references/checklist.md
**Target**: `contracts/src/AuditAnchor.sol` (+ its off-chain consumers in `packages/core/src/audit/` and `packages/cli/src/cli.ts`)
**Date**: 2026-09-18

The contract holds no funds. The guarantee it sells is _availability of proof_: "any audit entry can later be
shown to have been committed, unaltered." Severity is calibrated against that guarantee — a state in which a
recorded decision can never again be proven on-chain is a permanent DoS of the product, even though no wei moves.

---

## [D-1] `commitBatch` returns no batch index; the client derives it from `getBatchCount() - 1`, which is racy and permanently unprovable when wrong

**Severity**: High
**Category**: evm-audit-dos
**Location**: `commitBatch()` — `contracts/src/AuditAnchor.sol:34-39`; consumer at `packages/core/src/audit/logger.ts:118-125`
**Description**: `commitBatch` is `external` with no return value, so a committer has no atomic way to learn which
index its own push landed at. `AuditLogger.flush()` works around this by issuing a _separate, later_ read:

```ts
const txHash = await this.anchorClient.commit(root, rows.length); // logger.ts:118
const operator = this.anchorClient.operatorAddress();
const idx = (await this.anchorClient.getBatchCount(operator)) - 1; // logger.ts:121
await this.store.markBatched(
  rows.map((r) => r.id),
  idx,
); // logger.ts:122-125
```

`getBatchCount()` reports the array length _at the time of the read_, not the index this transaction produced.
Any additional `commitBatch` from the same operator key between the commit's mine and the `getBatchCount()` read
makes `idx` point at somebody else's batch. That is not hypothetical here: the committer identity is a single
shared secret (`ANCHOR_COMMITTER_KEY`), and the codebase has at least three independent flush paths that can hold
it concurrently — `agentctl serve` (`Guard.anchorAudit()`, `packages/core/src/index.ts:197`), a second CLI process,
and any host embedding `@agentctl/core`. Two concurrent flushes both read the post-state length and both tag their
rows with the same `idx`.

The consequence is unrecoverable. `proofFor()` (`logger.ts:130-149`) rebuilds a Merkle tree from
`entriesInBatch(batchIndex)` — i.e. from _whatever rows carry that tag locally_. If the tag is wrong, the rebuilt
leaf set differs from the set that produced the committed root, so `batch.root()` ≠ the on-chain
`batches[operator][idx].merkleRoot` and `verifyEntry()` returns `false` forever. The contract is append-only and
has no owner, no upgrade path, and no way to re-point or re-commit an index, so every affected entry is permanently
unverifiable. The CLI reports this as `✗ MISMATCH` (`packages/cli/src/cli.ts:490-495`) — indistinguishable from
actual log tampering, which is precisely the signal the system exists to produce.

The contract already emits the authoritative value — `BatchCommitted(operator, batchIndex, ...)` with `batchIndex`
indexed (`AuditAnchor.sol:26-31, 38`) — and `AuditAnchorClient.commit()` already awaits the receipt that contains
it (`packages/core/src/audit/anchor.ts:85-87`), then discards it and returns only `txHash`. The correct index is
fetched and thrown away in favour of a racy re-read.
**Proof of Concept**:

1. Deploy `AuditAnchor`. One operator key `K` is configured in two processes: `agentctl serve` and a cron'd flush.
2. Process A `flush()`es 40 rows → `commitBatch(rootA, 40)` mines as index 7.
3. Before A's `getBatchCount()` RPC returns, process B `flush()`es its own pending rows → `commitBatch(rootB, 12)`
   mines as index 8.
4. A's `getBatchCount()` now returns 9; A computes `idx = 8` and calls `markBatched(rowsA, 8)`.
   B's read also returns 9; B computes `idx = 8` and calls `markBatched(rowsB, 8)`.
5. Locally, batch 8 now contains 52 rows. `proofFor()` on any of them builds a 52-leaf tree whose root matches
   neither `rootA` (at index 7, now orphaned and referenced by nothing) nor `rootB` (at index 8).
6. `agentctl audit --verify` prints `✗ MISMATCH` for all 52 entries, permanently. No contract call can repair it.

A single-process variant reaches the same end state via [D-2] with no concurrency at all.
**Recommendation**: Return the index from the contract so the client never has to guess:

```solidity
function commitBatch(bytes32 merkleRoot, uint256 entryCount) external returns (uint256 batchIndex) {
    batchIndex = batches[msg.sender].length;
    batches[msg.sender].push(
        Batch({merkleRoot: merkleRoot, timestamp: block.timestamp, entryCount: entryCount})
    );
    emit BatchCommitted(msg.sender, batchIndex, merkleRoot, entryCount);
}
```

A return value is not readable from a broadcast transaction, so pair it with the client fix, which is the one that
actually closes the race: in `AuditAnchorClient.commit()`, keep the receipt already being awaited at `anchor.ts:85`
and decode `batchIndex` from its `BatchCommitted` log (`viem`'s `parseEventLogs`), returning `{ txHash, batchIndex }`.
Then drop the `getBatchCount() - 1` derivation at `logger.ts:121` entirely. Additionally, serialize `flush()` with a
store-level lock (a `SELECT ... FOR UPDATE` row or a SQLite `BEGIN IMMEDIATE`) so one committer key cannot have two
in-flight commits regardless.

---

## [D-2] `flush()` marks rows batched only after a receipt wait that times out at 180s; a slow-mining commit orphans the root and desynchronizes every later index

**Severity**: Medium
**Category**: evm-audit-dos
**Location**: `packages/core/src/audit/logger.ts:110-127`, `packages/core/src/audit/anchor.ts:76-88`
**Description**: The checklist's _block stuffing to prevent time-sensitive actions_ item applies to the commit path.
`AuditAnchorClient.commit()` calls `waitForTransactionReceipt({ hash })` with no `timeout`, `retryCount`, or
`confirmations` override, so viem's defaults apply — `timeout = 180_000` ms and `confirmations = 1`
(`viem@2.53.1/actions/public/waitForTransactionReceipt.ts:150-152`). On a congested L2, or with a fee-underpriced
transaction, or across an RPC provider outage, the wait throws `WaitForTransactionReceiptTimeoutError` while the
transaction is still queued — and then mines a minute later.

`flush()` performs the on-chain write and the local tagging as two non-atomic steps with no persisted intent
between them:

```ts
const txHash = await this.anchorClient.commit(root, rows.length); // throws on timeout
const idx = (await this.anchorClient.getBatchCount(operator)) - 1; // never reached
await this.store.markBatched(
  rows.map((r) => r.id),
  idx,
); // never reached
```

When the throw happens, the root _is_ committed on-chain but no row is tagged. Every row stays `batch_index IS NULL`,
so the next `flush()` re-selects them via `unbatched()` (`store.ts:144-149`), adds whatever has accrued since, builds a
**different** tree, and commits a **second** root at index N+1. The first root at index N is now referenced by nothing
and can never be proven against — it is dead state. Worse, the process is self-perpetuating under sustained
congestion: each retry burns gas, appends another orphan root, and grows the pending set. There is no reconciliation
routine, no `pending_commit` record, and `AnchorConfig.intervalMs` (`logger.ts:12`) is declared but never read
anywhere in the repo, so nothing retries or repairs automatically.

Distinct from [D-1] in mechanism (non-atomic commit→tag with no crash recovery, vs. a racy index read) and in fix,
but it reaches the same terminal state and needs only one process plus a congested block to get there.
**Proof of Concept**:

1. Configure anchoring against Base Sepolia. Accrue 200 unanchored entries.
2. Call `Guard.anchorAudit()`. `commitBatch(rootA, 200)` broadcasts at a base fee below the current floor.
3. The transaction sits in the mempool for >180s. `waitForTransactionReceipt` rejects; `flush()` propagates the
   throw. `markBatched` never runs — all 200 rows remain `batch_index IS NULL`.
4. The transaction mines shortly after. `batches[operator][0] = rootA` is now permanent and unreferenced.
5. The operator retries. 210 rows are now unbatched (10 accrued meanwhile); `commitBatch(rootB, 210)` lands at
   index 1 and tags all 210 rows with `batchIndex = 1`.
6. `rootA` at index 0 is permanently orphaned. The operator has paid for two commits and can prove against one.
   The count of on-chain batches no longer equals the count of logical batches, so any external auditor reconciling
   `getBatchCount()` against the local DB sees an unexplained extra root — exactly the discrepancy an anchor is
   meant to rule out.
   **Recommendation**: Make the commit→tag sequence crash-safe. Write a `pending_commit` row (`txHash`, the ordered
   entry ids, the local root) to the store _before_ broadcasting; tag rows from that record once the receipt is
   observed; and on startup, resolve any `pending_commit` by looking up its `txHash` — if it mined, complete the
   tagging from its `BatchCommitted` log (which also supplies the correct index per [D-1]); if it was dropped, clear
   the record and let the rows re-batch. Pass an explicit `timeout` and `retryCount` to `waitForTransactionReceipt`,
   and on `WaitForTransactionReceiptTimeoutError` do **not** treat the batch as unanchored — resume polling the same
   hash rather than committing a fresh root. Never let a timeout be the trigger for a second `commitBatch`.

---

## [D-3] `flush()` imposes no batch size cap and `proofFor()` rebuilds the full batch tree per entry, making `audit --verify` O(N²)

**Severity**: Medium
**Category**: evm-audit-dos
**Location**: `packages/core/src/audit/logger.ts:110-149`, `packages/cli/src/cli.ts:482-496`
**Description**: This is the checklist's _user-growable structure iterated in a loop_ item, displaced from the
contract into the off-chain verifier — the contract stores only a root and so imposes no limit on how many entries
one batch may represent, and nothing in the pipeline adds one.

`flush()` selects **every** unbatched row (`store.unbatched()` has no `LIMIT`, `store.ts:144-149`) and pushes all of
them into a single `MerkleAuditBatch` (`logger.ts:112-117`). Because `AnchorConfig.intervalMs` is never wired up,
flushing is entirely manual, so a deployment that anchors monthly, or one that simply forgets to, accumulates an
arbitrarily large single batch.

Verification then quadratically amplifies that size. `proofFor(entryId)` calls `entriesInBatch(batchIndex)` and
constructs a fresh `StandardMerkleTree` over the **entire** batch to extract one proof (`logger.ts:133-141`;
`MerkleAuditBatch.build()` at `merkle.ts:46-51` caches only per-instance, and `proofFor` allocates a new instance
each call). `verifyEntries()` calls `proofFor` once per entry inside its loop (`cli.ts:482-483`). For a batch of N
entries, that is N full tree constructions over N leaves each — O(N²) hashes and O(N²) allocation churn, for a
result that is identical every time.

At N = 1,000 this is ~10⁶ leaf-hash operations and a visible stall. At N = 100,000 it is ~10¹⁰ and the command is
unusable — it will exhaust the Node heap or run for hours. The failure lands squarely on the availability of the
integrity guarantee: an operator who anchored diligently still cannot demonstrate it. Note the on-chain side is
_not_ the bottleneck — a StandardMerkleTree proof is ⌈log₂ N⌉ elements, so even N = 10⁶ yields a 20-element proof
(see [D-5]); the entire cost is off-chain and entirely avoidable.
**Proof of Concept**:

1. Run an agent that records 50,000 decisions without anchoring (the default, since nothing schedules `flush()`).
2. Call `anchorAudit()` once. `unbatched()` returns all 50,000 rows; one `commitBatch(root, 50000)` is sent.
3. Run `agentctl audit --verify`. The loop at `cli.ts:482` calls `proofFor` 50,000 times; each call runs
   `StandardMerkleTree.of()` over 50,000 leaves — ~2.5 × 10⁹ leaf hashes plus 50,000 × 50,000 tuple allocations.
4. The process stalls indefinitely or dies with `JavaScript heap out of memory`. No entry is verified, including
   entries that are perfectly valid.
   **Recommendation**: Two independent fixes, both worth making.
   (a) Cap batch size at flush: chunk `unbatched()` into slices of a bounded size (e.g. 4,096) and emit one
   `commitBatch` per chunk, so no batch can grow past a size the verifier can rebuild. Add a `LIMIT` to
   `AuditStore.unbatched()` and loop.
   (b) Build each batch tree once, not per entry: add a `proofsForBatch(batchIndex)` to `AuditLogger` that constructs
   the tree a single time and returns a `Map<entryId, EntryProof>`, and have `verifyEntries()` group entries by
   `batchIndex` and call it once per batch. That alone collapses O(N²) to O(N log N). Also consider persisting the
   committed leaf ordering so proofs never depend on re-deriving row order from `ORDER BY rowid`.

---

## [D-4] `audit --verify` issues 2 serial, uncached, unguarded RPC calls per entry — one transient failure or rate-limit aborts the whole run

**Severity**: Medium
**Category**: evm-audit-dos
**Location**: `verifyEntries()` — `packages/cli/src/cli.ts:482-496`
**Description**: The checklist's _external calls inside a loop_ pattern, applied to the verifier. The loop body is:

```ts
for (const e of await log.list({ agentId: agent })) {
  const proof = await log.proofFor(e.id);
  if (!proof) { ...; continue; }
  const batch  = await anchor.getBatch(operator, proof.batchIndex);       // cli.ts:488
  const onchain = await anchor.verifyEntry(operator, proof.batchIndex, proof.leaf, proof.proof); // cli.ts:489
  ...
}
```

Three compounding problems:

1. **No error handling.** Neither `await` is wrapped. Both `getBatch` and `verifyEntry` go through
   `makePublicClient(...).readContract` (`anchor.ts:104-110, 130-136`), which rejects on any RPC-layer failure —
   HTTP 429, a 5xx from the node, a dropped connection, a revert ([D-6]). A rejection propagates out of
   `verifyEntries`, out of the `audit` action, and into the top-level `program.parseAsync().catch()` at
   `cli.ts:392-395`, which prints one line and sets exit code 1. Entry #4,999 failing discards the verification
   status of entries #1–#4,998 that had already been confirmed. The command is all-or-nothing with no partial
   result and no resume point.

2. **Redundant reads.** `getBatch(operator, proof.batchIndex)` returns the same root for every entry sharing a
   batch — and per [D-3] a batch commonly contains _all_ entries. Verifying 5,000 entries in one batch fetches
   the identical `batches(operator, 0)` tuple 5,000 times.

3. **Serial and unthrottled.** 2N round-trips are issued back-to-back with no concurrency limit and no backoff.
   The default endpoint is the public `https://sepolia.base.org` (`packages/core/src/constants.ts:40`); public
   Base RPCs rate-limit aggressively. A few thousand entries reliably trips 429, which by problem (1) is fatal.

Net effect: for any non-trivial audit log, `--verify` fails to produce a verdict — the availability failure matters
more than any single call's cost.
**Proof of Concept**:

1. Anchor 5,000 entries (one batch, per [D-3]) and run `agentctl audit --verify` against `https://sepolia.base.org`.
2. The loop issues 10,000 `eth_call`s serially, 5,000 of them byte-identical `batches(operator, 0)` reads.
3. The public endpoint returns HTTP 429 partway through. `readContract` rejects.
4. The rejection unwinds to `cli.ts:392`. Output is `error: HTTP request failed. Status: 429` and exit code 1.
   Nothing indicates how many entries verified before the failure, and rerunning restarts from entry 1 and trips
   the same limit.
   **Recommendation**: Group entries by `batchIndex` and fetch `getBatch` **once per batch**, not once per entry
   (pairs naturally with the [D-3] fix). Wrap each RPC in `try/catch` and record a per-entry `error` status so one
   failure degrades that row rather than the run. Add bounded concurrency plus exponential backoff on 429/5xx
   (`viem`'s `http({ retryCount, retryDelay })` transport options, currently left at defaults in
   `makePublicClient`). Print a summary (`verified / mismatched / errored / not-anchored`) and exit non-zero only on
   a genuine mismatch, so an infrastructure hiccup is never reported as an integrity failure. For large logs, verify
   the batch root once and check the remaining proofs locally against it — only the root genuinely needs the chain.

---

## [D-5] `verifyEntry` iterates an unbounded caller-supplied `proof` array with no length cap

**Severity**: Low
**Category**: evm-audit-dos
**Location**: `verifyEntry()` — `contracts/src/AuditAnchor.sol:42-56`
**Description**: The loop at line 50 runs `proof.length` iterations with no upper bound, and `proof` is
attacker-controlled `calldata`. Each iteration is a `keccak256` over 64 bytes plus a calldata load — cheap
individually, unbounded in aggregate.

Impact today is genuinely limited, and I want to be explicit about why rather than inflate it. `verifyEntry` is
`view`; no on-chain contract calls it, and the only consumer is `eth_call` from `AuditAnchorClient.verifyEntry`
(`anchor.ts:98-111`). An `eth_call` is metered against the node's own gas cap (commonly 50M), so an oversized
proof simply returns an out-of-gas error — it does not consume block space, cannot be mined, and costs other users
nothing. Legitimate proofs are tiny regardless: a StandardMerkleTree proof is ⌈log₂ N⌉ elements, so even a
1,000,000-entry batch produces a 20-element proof. There is no realistic path from honest use to a large `proof`.

What keeps it on the list is that the function is `external` and permanently deployed, so the bound is inherited by
callers the author does not control:

- **Any future on-chain integrator** — a contract gating a payout, a slashing condition, or a dispute resolver on
  `AuditAnchor.verifyEntry(...)` — accepts an attacker-chosen gas bound inside its own transaction. A 300,000-element
  proof is ~90M gas of hashing, above the Base block gas limit, permanently reverting whatever wraps it. The
  contract cannot be upgraded to add a cap later.
- **Public RPC exposure** — an unauthenticated caller can spend a node's entire per-call gas budget for the cost of
  submitting calldata, with zero on-chain cost. If the project fronts its own RPC for a verification UI, this is a
  free asymmetric load generator.

Minor and separate: the loop uses a checked `i++` (line 50) where `unchecked { ++i; }` is safe, and re-reads
`proof[i]` twice per iteration (lines 51-53) — no security impact, just avoidable gas.
**Proof of Concept**:

```bash
# 300,000-element proof against a real batch; ~90M gas of keccak, above Base's block gas limit.
cast call $ANCHOR "verifyEntry(address,uint256,bytes32,bytes32[])(bool)" \
  $OPERATOR 0 $LEAF "[$(python3 -c 'print(",".join(["0x"+"11"*32]*300000))')]" \
  --rpc-url https://sepolia.base.org
# → out of gas. Zero cost to the caller beyond bandwidth; the node performs the work.
```

Now suppose a `PayoutOnProof` contract calls `anchor.verifyEntry(op, idx, leaf, proof)` with a user-supplied proof.
The same array makes that call exceed the block gas limit, so the payout path reverts for every caller and cannot
be fixed in `AuditAnchor`.
**Recommendation**: Cap the proof length against what the tree depth can justify, and reject anything larger:

```solidity
uint256 private constant MAX_PROOF_LENGTH = 64; // 2^64 leaves — far beyond any real batch

error ProofTooLong(uint256 length);

if (proof.length > MAX_PROOF_LENGTH) revert ProofTooLong(proof.length);
```

While editing, tighten the loop: `for (uint256 i; i < proof.length;) { bytes32 p = proof[i]; computed = computed < p
? keccak256(abi.encodePacked(computed, p)) : keccak256(abi.encodePacked(p, computed)); unchecked { ++i; } }`.
Prefer replacing the hand-rolled loop with OpenZeppelin's `MerkleProof.verifyCalldata`, which is audited and
matches the `StandardMerkleTree` encoding the client already relies on (`merkle.ts:1-14`).

---

## [D-6] Out-of-range `batchIndex` reverts with `Panic(0x32)` instead of returning `false`, turning a configuration mistake into a total verification failure

**Severity**: Medium
**Category**: evm-audit-dos
**Location**: `verifyEntry()` — `contracts/src/AuditAnchor.sol:48`; `batches` public getter — `AuditAnchor.sol:24`
**Description**: `batches[operator][batchIndex]` (line 48) performs a bounds-checked array index. Solidity ≥0.8
compiles this to a revert with `Panic(0x32)` (array out-of-bounds) when `batchIndex >= batches[operator].length` —
including the very common case of an operator with **zero** batches, where every index panics. The auto-generated
`batches(address,uint256)` getter behaves identically.

A predicate function that reverts instead of returning `false` is a poor boundary for a verifier: the natural
answer to "is this entry in batch #7 of this operator?" when batch #7 does not exist is _no_, not _abort_. Combined
with [D-4]'s missing `try/catch`, a single out-of-range index destroys the entire run. And out-of-range indices
arise from ordinary operational mistakes, not attacks:

- **Operator mismatch.** `verifyEntries` derives `operator` from whatever `ANCHOR_COMMITTER_KEY` is in the
  environment _at verification time_ (`cli.ts:469, 480`). Verify with a different key than the one that committed —
  a rotated key, a CI secret, a teammate's `.env` — and `batches[thatAddress].length == 0`, so the **first**
  `getBatch` call panics and every subsequent entry is never reached.
- **Contract redeploy.** `AUDIT_ANCHOR_ADDRESS` points at a fresh deployment while the SQLite DB still carries
  `batch_index` values from the old one. Every index is out of range.
- **Orphaned/desynchronized indices** from [D-1] and [D-2].

In all three cases the user sees `error: ... reverted ... Panic(0x32)` and exit code 1, with no indication that the
cause is a wrong operator address or a stale database rather than a corrupted audit log. For a tool whose output is
meant to be evidence, "the verifier crashed opaquely" and "the log was tampered with" must not be the same signal.
**Proof of Concept**:

1. Anchor entries with committer key `K1`; local rows carry `batch_index = 0`.
2. Rotate to `K2` (or run verification on a second machine whose `.env` holds a different key) and run
   `agentctl audit --verify`.
3. `operator = address(K2)`, for which `getBatchCount(operator) == 0`.
4. The first iteration calls `anchor.getBatch(operator, 0)` → `batches(address,uint256)` → `Panic(0x32)` → viem
   `ContractFunctionExecutionError` → unhandled rejection → `cli.ts:392` prints `error: ...` and exits 1.
5. Not one entry is checked, and nothing in the output points at the key as the cause. An operator debugging this
   has no reason to suspect their key rather than their log.
   **Recommendation**: Make the contract answer the question instead of aborting:

```solidity
function verifyEntry(address operator, uint256 batchIndex, bytes32 leaf, bytes32[] calldata proof)
    external view returns (bool)
{
    if (batchIndex >= batches[operator].length) return false;
    ...
}
```

Add an explicit, non-reverting reader for metadata so consumers can distinguish "no such batch" from "bad root" —
e.g. `function tryGetBatch(address operator, uint256 batchIndex) external view returns (bool exists, Batch memory b)`.
On the client side (fixing the current deployment without a redeploy): in `verifyEntries`, call
`anchor.getBatchCount(operator)` **once** before the loop and fail fast with a targeted message when it is `0` or
`<= max(batchIndex)` — "operator `0x…` has N batches on `$AUDIT_ANCHOR_ADDRESS`; local entries reference batch #M —
wrong `ANCHOR_COMMITTER_KEY` or wrong contract?" — and wrap the per-entry reads in `try/catch` per [D-4].

---

## [D-7] `commitBatch` is permissionless, unmetered, and unbounded — cheap permanent state growth on the L2 target

**Severity**: Low
**Category**: evm-audit-dos
**Location**: `commitBatch()` — `contracts/src/AuditAnchor.sol:34-39`; `mapping(address => Batch[]) public batches` — line 24
**Description**: `commitBatch` has no access control, no fee, no rate limit, no per-operator cap, and no minimum.
Anyone may append arbitrarily many `Batch` structs. The checklist flags _array-filling attacks are economically
viable on L2s_ — and the deployment target is Base (`eip155:84532` default, Base mainnet configured at
`packages/core/src/constants.ts:30-52`), where gas is near-free. This warrants careful scoping, because the usual
version of this bug is much worse than what is actually here.

**What is NOT exploitable — and this is the load-bearing detail.** The array is keyed by `msg.sender`
(`batches[msg.sender].push(...)`, line 35), never by a caller-supplied address. There is therefore **no way for an
attacker to grief a specific operator**:

- An attacker cannot append to a victim's array, so a victim's `getBatchCount(victim)` is unaffected by any amount
  of external spam and their batch indices never shift.
- Existing indices are immutable — entries are only ever pushed, never inserted or removed — so no previously
  issued proof can be invalidated by a third party.
- No function iterates `batches[...]` on-chain; all access is O(1) by index (lines 48, 59). Growth in one array does
  not raise the cost of reading any element, so the classic "fill the array until the loop exceeds the block gas
  limit" DoS has no target here.
- `proof.length` is driven by tree depth, not by batch count, so array growth does not inflate [D-5] either.
- I confirmed no off-chain consumer walks the array or scans events: `getBatchCount` is called exactly once
  (`logger.ts:121`) to derive a single index, and `grep` for `getLogs` / `watchEvent` / `watchContractEvent` /
  `BatchCommitted` across `packages/` and `crates/` returns nothing. Nothing enumerates batches.

**What remains** is a pure state-growth externality. Each `commitBatch` writes three cold 32-byte slots
(root/timestamp/count) plus the array-length slot — roughly 66k gas for an operator's first push and ~45–66k after —
and that storage is permanent and unreclaimable, with no `SSTORE`-to-zero refund path since nothing is ever deleted.
On Base at ~0.005 gwei, a single commit costs a small fraction of a cent, so a few hundred dollars buys millions of
permanently resident slots. The cost is borne diffusely by node operators (state size, sync time, and exposure to
any future state-rent or state-expiry scheme), not by any protocol participant, and there is no victim who loses a
guarantee. That is why this is Low and not higher.

**Latent secondary concern.** `BatchCommitted` (lines 26-31) is emitted for every caller with `operator` indexed.
Nothing consumes logs today, but any future indexer, subgraph, or dashboard that subscribes to `BatchCommitted`
without filtering on the expected operator topic would be trivially flooded for pennies — the checklist's L2
array-filling item reappearing at the indexing layer. Worth pinning down before an indexer is written.
**Proof of Concept**:

```solidity
contract Filler {
    function spam(AuditAnchor a, uint256 n) external {
        for (uint256 i; i < n; ++i) a.commitBatch(bytes32(i), 0);
    }
}
```

Roughly 300 commits fit in one Base block from a single sender; sustained over a day at ~0.005 gwei this appends
millions of permanent `Batch` structs for a few hundred dollars in fees, and emits an equal number of
`BatchCommitted` events. Crucially, `getBatchCount(honestOperator)` is **unchanged** throughout and every existing
proof still verifies — the harm is to chain state and to any unfiltered log consumer, not to the protocol's users.
**Recommendation**: Given no operator-specific harm, the contract is defensible as-is; the fix is proportionate to
how public the deployment is.

- If the anchor is meant for a known set of committers, add an allowlist (`mapping(address => bool) isOperator`
  with an owner, or an `AccessControl` role) gating `commitBatch`. This is the cleanest option and also bounds the
  event stream.
- If it must stay permissionless, add a minimal anti-spam rule that costs honest operators nothing — e.g. reject
  `entryCount == 0`, and require a minimum block spacing between an operator's commits
  (`require(block.timestamp > lastCommit[msg.sender] + MIN_INTERVAL)`), which suits a batching anchor's real usage.
- Regardless: when an indexer is built, always filter `BatchCommitted` by the expected `operator` topic, and never
  page through `batches[...]` by iterating indices from an untrusted `getBatchCount`.

---

## [D-8] `entryCount` is stored unvalidated, uncorrelated with the root, and unused — a latent attacker-controlled loop bound for future consumers

**Severity**: Info
**Category**: evm-audit-dos
**Location**: `commitBatch()` — `contracts/src/AuditAnchor.sol:34-38`; `Batch.entryCount` — line 20
**Description**: `entryCount` is accepted as an arbitrary `uint256`, stored verbatim, and never checked against
anything. Nothing ties it to the committed `merkleRoot` — a caller may commit a root over 2 leaves while declaring
`entryCount = type(uint256).max`, or `0`. It is advisory metadata masquerading as a verified count.

No current consumer is harmed: `getBatch` returns it (`anchor.ts:129-137`) but the CLI reads only `batch.root`
(`cli.ts:490`), and I confirmed by grep that no code in `packages/` or `crates/` uses `entryCount` as a loop bound
or a length. Hence Info, not a live finding.

It is worth recording because it is exactly the shape that becomes the checklist's _attacker-controlled loop bound_
the moment someone writes the obvious consumer. A verification dashboard doing `for (let i = 0; i < batch.entryCount;
i++)`, or preallocating `new Array(batch.entryCount)`, hangs or OOMs on a hostile value. The conversion in
`anchor.ts:137` (`Number(entryCount)`) silently loses precision above 2⁵³ and yields `Infinity`-adjacent nonsense
rather than an error, so the bad value propagates quietly into JS. The field also creates a false impression of
verification in a product whose entire premise is verifiability.
**Proof of Concept**:

```solidity
anchor.commitBatch(keccak256("two-leaf-root"), type(uint256).max);
```

`getBatch(op, idx).entryCount` then returns `1.157920892373162e+77` after `Number()` conversion. Any consumer
looping to that bound never terminates; any consumer preallocating to it throws `RangeError: Invalid array length`.
The committed root remains perfectly valid, so nothing flags the batch as suspect.
**Recommendation**: Bound it at the boundary — `if (entryCount == 0 || entryCount > MAX_ENTRIES_PER_BATCH) revert
InvalidEntryCount();` with `MAX_ENTRIES_PER_BATCH` matching the flush cap from [D-3]. Narrow the storage type to
`uint64` (which also packs `timestamp` and `entryCount` into one slot with a `uint64` timestamp, cutting [D-7]'s
per-commit cost by one `SSTORE`). Document that `entryCount` is operator-asserted and not cryptographically bound
to the root, and never let an off-chain consumer use it as a loop bound or an allocation size — derive both from
the locally stored batch contents instead.

---

# Cleared

Checklist items walked and found not applicable, with the reason each was closed.

**Gas Griefing**

- _Returndata bombing via external calls_ — **Cleared.** `AuditAnchor` makes no external calls of any kind: no
  `.call`, `delegatecall`, `staticcall`, or interface call appears in the file. There is no callee that could
  return data into its memory.
- _Insufficient gas forwarding (SWC-126)_ — **Cleared.** No `.call{gas: X}()` and no external calls at all, so
  there is no inner call whose gas could be starved by a precisely sized outer call.
- _Try/catch always fails with insufficient gas_ — **Cleared on-chain**: no `try/catch` in the contract. The
  off-chain analogue — the verifier having _no_ error handling around its RPC calls — is filed as **[D-4]**.

**Unbounded Loops**

- _User-growable arrays iterated in a loop_ — **Cleared for the contract.** `batches[operator]` is user-growable
  but is never iterated on-chain; both read paths index it in O(1) (`AuditAnchor.sol:48`, `:59`). Array growth
  therefore cannot push any function past the block gas limit. Because the array is keyed by `msg.sender`, an
  attacker also cannot grow a _victim's_ array, which is what would make this exploitable. The growth that does
  occur is filed as a state-growth externality in **[D-7]**, and the real unbounded iteration lives off-chain in
  **[D-3]**.
- _External calls inside loops_ — **Cleared on-chain** (no external calls, no loops over recipients). Filed
  off-chain as **[D-4]** (2 RPC calls per entry, serial, uncached, unguarded).
- _On L2s with cheap gas, array-filling attacks are economically viable_ — **Applies**, and is filed as **[D-7]**;
  scoped to Low there because the per-sender keying removes any specific victim.

**Revert-Based DoS**

- _ETH receiver with reverting fallback_ — **Cleared.** The contract never sends ETH. It holds no balance, has no
  `payable` function, and defines no `receive`/`fallback`, so ETH sent to it reverts — correct for a contract with
  no withdrawal path and no risk of locked funds.
- _Token transfer to blocklisted address_ — **Cleared.** No ERC-20 interaction anywhere; no batch distribution
  function exists.
- _Zero-amount transfer reverts_ — **Cleared.** No token transfers, and no reward/claim accounting that could
  round to zero.

**Block Stuffing & Time-Based DoS**

- _Block stuffing to prevent time-sensitive actions_ — **Cleared for the contract.** `block.timestamp` is recorded
  at line 36 but is never compared against anything: there is no deadline, auction window, grace period, expiry, or
  liquidation window, so no action can be pushed past a cutoff. The one time-sensitive path in the system is the
  off-chain commit's 180-second receipt wait, which congestion _can_ blow through — filed as **[D-2]**.
- _Timelock-based griefing at no cost_ — **Cleared.** No timelock, no delay, no queue, and no restartable pending
  action. Commits take effect in the transaction that makes them.

**Economic Griefing**

- _Front-running liquidation griefing_ — **Cleared.** No liquidations, no collateral, no health factor, and no
  economic state at all. The front-running analogue worth checking — inserting a batch ahead of a victim to shift
  their indices — is impossible because `batches` is keyed by `msg.sender`; the residual same-key race is filed as
  **[D-1]**.
- _Account abstraction DoS via free paymaster_ — **Cleared.** No ERC-4337 integration: no `validateUserOp`, no
  paymaster, no EntryPoint. `commitBatch` callers pay their own gas, which is what keeps **[D-7]** at Low rather
  than free.

**Pause-Related DoS**

- _Pausing liquidations creates solvency risk_ — **Cleared.** No pause mechanism and no liquidations; the contract
  has no solvency dimension.
- _Pause can brick contract_ — **Cleared.** No `Pausable`, no `whenNotPaused` modifier, no owner, and no admin
  function of any kind, so no path exists to permanently disable `commitBatch` or `verifyEntry`. (The flip side —
  that a compromised committer key cannot be revoked, and that no batch can ever be corrected — is an
  access-control/upgradeability concern outside this domain, though it is what makes **[D-1]** and **[D-2]**
  unrecoverable and is why they are rated as permanent.)

**Oracle DoS**

- _Chainlink multisig can block price feed access_ — **Cleared.** No oracle, no price feed, no `latestRoundData`
  call. The contract stores only caller-supplied bytes32 roots.
- _`balanceOf()` reverting causes DoS_ — **Cleared.** No ERC-20 calls; `balanceOf` appears nowhere in the contract
  or its call graph.

**Scope note.** Findings **[D-2]**, **[D-3]**, and **[D-4]** live in off-chain code rather than in
`AuditAnchor.sol`. They are included because the brief directs this domain to assess whether off-chain consumers
iterate the anchor's data unboundedly, and because each is the direct consequence of a contract-side design gap —
no batch-size bound, no returned index, revert-on-out-of-range — that is now immutable on-chain and must be
compensated for by the client.
