# Access Control Findings — AuditAnchor.sol

**Domain**: `evm-audit-access-control`
**Target**: `contracts/src/AuditAnchor.sol`
**Off-chain context reviewed**: `packages/core/src/audit/logger.ts`, `packages/core/src/audit/anchor.ts`, `packages/core/src/audit/merkle.ts`, `packages/core/src/audit/store.ts`, `packages/core/src/audit/postgres-store.ts`, `packages/cli/src/cli.ts`, `contracts/script/Deploy.s.sol`, `contracts/test/AuditAnchor.t.sol`
**Claim under test**: "a tamper-evident audit trail — proves a log entry wasn't altered after commitment" (README line 6, limitation 4 at README line 184)

No funds are held by this contract. Severity is calibrated against the integrity guarantee the product sells, not against value at risk.

---

## [AC-1] Operator identity is a single hot EOA with no rotation, revocation, or repudiation path

**Severity**: High
**Category**: evm-audit-access-control
**Location**: `commitBatch()` / `AuditAnchor.sol:24,34`; `packages/core/src/audit/anchor.ts:92` (`operatorAddress()`); `.env.example:44` (`ANCHOR_COMMITTER_KEY`)
**Description**: The only notion of identity in the system is `msg.sender`. The mapping key `batches[address]` _is_ the operator. There is no registry, no role, no successor pointer, no revocation list, and no event other than `BatchCommitted`. Three lifecycle events that are certainties over the life of an audit system are all unhandled:

- **Key rotation.** Rotating the committer key starts a brand-new, empty `batches[newAddr]` array. Nothing on chain links the old address's history to the new one, and nothing declares the old address retired. A verifier holding proofs against the old address cannot tell "retired cleanly at batch N" from "still live and still authoritative". Both addresses remain permanently, equally valid committers forever.
- **Key compromise.** An attacker who obtains the key can append arbitrary roots under the operator's identity indefinitely. There is no pause, no `revoke`, no owner, no way for the operator to publish "batches after index N are not mine". Because commits carry no signature over anything but the transaction itself, a forged batch is byte-for-byte indistinguishable from a genuine one. The compromise is unrecoverable by design, and the contract is immutable, so it cannot be patched.
- **Key loss.** The anchored chain simply ends. Entries already committed stay provable, but the operator has no way to continue the same identity; they must silently become a different operator.

This is aggravated by where the key lives. `AuditLogger` constructs `AuditAnchorClient` with `anchor.committerKey` held in the same process that evaluates payment policy (`logger.ts:62-72`), sourced from `ANCHOR_COMMITTER_KEY` in the agent's environment. The party being audited holds the anchoring key hot and online, in the same trust boundary as the log it anchors. A host compromise therefore yields both the SQLite log and the anchoring authority at once, which is exactly the pairing that makes [AC-2] executable end-to-end by a third party rather than only by a dishonest operator.

Checklist mapping: _"Corrupted owner can destroy the protocol"_ — here the corrupted party destroys the guarantee rather than funds, and there is neither multisig, timelock, nor any recovery affordance. _"Roles granted in constructor but not documented"_ — inverted: no roles exist at all, so the effective role (any EOA that has ever committed) is undocumented and unbounded.

**Proof of Concept**:

```
1. Operator runs with ANCHOR_COMMITTER_KEY = k, address A. Batches 0..N committed.
2. Attacker exfiltrates k from the agent host (env var, .env file, process memory,
   or the CI/deploy environment — Deploy.s.sol reads the same variable).
3. Attacker calls commitBatch(anyRoot, anyCount) from A. It succeeds.
   - No modifier, no signature over batch content, no nonce, no deadline.
4. Operator notices. Available remedies on chain: none.
   - No pause()       -> cannot stop further commits.
   - No owner/admin   -> cannot transfer or freeze the identity.
   - No revoke/retire -> cannot mark batches > N repudiated.
   - No upgrade       -> cannot add any of the above.
5. Every consumer of `verifyEntry(A, ...)` continues to treat A as authoritative,
   for both the pre- and post-compromise batches, permanently.
```

The same script with step 2 replaced by "operator loses k" produces a permanently truncated audit chain with no on-chain marker that it ended.

**Recommendation**:

- Separate the _anchoring_ authority from the _agent_ process. The committer key should not live in the environment of the process producing the log. At minimum, move commits behind a signer the agent cannot read (KMS/HSM, a separate signing service, or a Safe).
- Make the operator identity a contract, not an EOA: commit through a Safe (or an `AccessControl`-bearing `Operator` contract) whose address is stable across key rotations. Then rotating a signer does not change `batches[operator]`, and a compromised signer can be removed by the remaining owners.
- Add explicit lifecycle state to the anchor so rotation and revocation are _observable_:
  ```solidity
  event OperatorRetired(address indexed operator, uint256 lastValidBatchIndex, address successor);
  event BatchesRepudiated(address indexed operator, uint256 fromBatchIndex, string reason);
  function retire(uint256 lastValidBatchIndex, address successor) external; // msg.sender-scoped
  ```
  These stay self-scoped (no admin introduced) but give verifiers a rule: batches with index > `lastValidBatchIndex` for a retired operator are not authoritative, and the successor address is the continuation. A compromised key can also publish a retirement, but so can the legitimate holder — and a race between the two is at least _visible_, which is strictly better than the current silence.
- Document, in the README limitations list, that the anchor's guarantee is bounded by custody of a single hot key and that key compromise is unrecoverable until the above exists.

---

## [AC-2] `commitBatch` is an unordered, unlinked append — the operator can equivocate and rewrite anchored history undetectably

**Severity**: High
**Category**: evm-audit-access-control
**Location**: `commitBatch()` / `AuditAnchor.sol:34-39`; `packages/core/src/audit/logger.ts:110-149` (`flush`/`proofFor`); `packages/cli/src/cli.ts:463-497` (`verifyEntries`); `packages/core/src/audit/store.ts:151-165`
**Description**: A root committed to `batches[msg.sender]` is bound to nothing. Not to a predecessor root, not to a logical sequence number, not to a covered time range, not to a set of entry IDs, and not to uniqueness. The array is append-only in the trivial sense that entries cannot be deleted, but append-only storage is not append-only _semantics_: the operator can publish a second, contradicting root at a later index and then point every consumer at it.

The off-chain verifier closes the loop in the operator's favour. `verifyEntries()` (cli.ts:482-495) iterates `log.list()` — rows that currently exist in the operator's own SQLite — and for each one calls `log.proofFor(e.id)`, which reads `batchIndex` from that same operator-controlled row (`logger.ts:130-133`, `getById` -> `store.getById`) and rebuilds the tree from `store.entriesInBatch(batchIndex)`, again operator-controlled. It then compares the rebuilt local root to `getBatch(operator, batchIndex).root` and calls `verifyEntry` on chain. Every input to that comparison except the on-chain root is chosen by the operator, and the on-chain root is one the operator freely chose to publish. The check answers "is this row consistent with _some_ root I published?" — not "is this the complete set of entries I committed to at the time?".

An omitted entry produces no output at all: the loop iterates existing rows, so a deleted row is not reported as missing, not reported as unverifiable, not reported at all. There is no completeness check anywhere in the path.

This is the direct negation of README limitation 4 ("It proves a log entry wasn't altered after commitment"). The property actually delivered is weaker: _an entry that the operator still chooses to show you is consistent with a root the operator still chooses to point you at_.

Checklist mapping: _"When all agents are the same person"_ (multi-agent access). The log producer, the batch selector, the committer, the `batchIndex` recorder, and the verifier are one key and one process. The cross-role interaction that is never tested is precisely "same address plays every role".

Not rated Critical: exploitation requires the operator to act dishonestly rather than being reachable by an arbitrary unprivileged third party, and no funds move. Rated High rather than Medium because the consequence is not degraded behaviour but the permanent and undetectable falsification of the system's sole advertised guarantee, relied on by third parties who have no way to detect it.

**Proof of Concept**:

```
Setup: operator A runs the agent; entries e1..e5 recorded, e3 is an "allow" the
operator later wants to disappear (say a $9,000 payment to a counterparty that
later turns out to be sanctioned).

1. guard.anchorAudit() -> logger.flush()
     rows = unbatched() = [e1..e5]
     R0   = StandardMerkleTree.of([e1..e5]).root
     commitBatch(R0, 5)              -> batches[A][0] = {R0, t0, 5}
     markBatched([e1..e5], 0)        -> sqlite batch_index = 0 for all five
   `agentctl audit --verify` prints five "verified on-chain" lines.

2. Weeks later, the operator rewrites history with two SQL statements and one tx:

     sqlite3 agentctl.sqlite "DELETE FROM audit_entries WHERE id='e3';"
     # (or, to alter rather than omit:
     #  UPDATE audit_entries SET request_json=..., entry_hash=... WHERE id='e3';)

     R1 = StandardMerkleTree.of([e1,e2,e4,e5]).root
     commitBatch(R1, 4)              -> batches[A][1] = {R1, t1, 4}   // accepted

     sqlite3 agentctl.sqlite "UPDATE audit_entries SET batch_index=1
                              WHERE batch_index=0;"

3. `agentctl audit --verify` now:
     - log.list()          -> e1,e2,e4,e5        (e3 is simply not iterated)
     - proofFor(e1)        -> batchIndex 1, tree over [e1,e2,e4,e5], localRoot=R1
     - getBatch(A,1).root  -> R1                 -> rootMatch = true
     - verifyEntry(A,1,leaf,proof) -> true
   Output: four lines, all "verified on-chain". Zero warnings. e3 has vanished
   from a "tamper-evident" log and the tool reports a clean bill of health.

4. What an independent observer sees on chain: batches[A][0] = (R0, t0, 5) and
   batches[A][1] = (R1, t1, 4). Nothing in the contract says batch 1 must extend
   batch 0, that entryCount must be non-decreasing, or that R0's leaf set must be
   a subset of R1's. R0 and R1 are unrelated 32-byte values; there is no way to
   compute from them that an entry was dropped, and no way to recover e3's leaf
   to demand a proof for it. The contradiction is unprovable even in principle
   from on-chain data alone.
```

Step 2 requires only the SQLite file and the committer key — both held by the agent host, which is why [AC-1]'s hot-key placement makes this reachable by a host attacker, not only by the operator.

**Recommendation**:

- **Chain the batches.** Make each commit bind to its predecessor so the sequence is a hash chain, not a bag:
  ```solidity
  mapping(address => bytes32) public head;         // last root, per operator

  function commitBatch(bytes32 merkleRoot, uint256 entryCount, bytes32 prevRoot) external {
      require(prevRoot == head[msg.sender], "stale or forked head");
      head[msg.sender] = merkleRoot;
      // ...
  }
  ```
  A rewrite then requires forking from an already-published head, and the fork is _visible_: the on-chain head no longer matches the root the verifier is being shown. The operator can still publish a new chain, but cannot do so silently.
- **Make the batch cumulative, not incremental.** If each root commits to _all_ entries to date (or to a running accumulator), then omitting an entry changes a root that was already published, rather than producing a fresh unrelated one.
- **Fix the verifier's trust in local `batchIndex`.** `verifyEntries()` must not take `batchIndex` from the operator's own row. Enumerate `BatchCommitted` logs for the operator from chain, reconstruct the expected batch set, and check that the local store accounts for _every_ on-chain batch and _every_ entry each batch claims (see [AC-4]). Report entries the chain knows about but the store cannot produce — that is the tamper signal that is currently absent.
- Emit a repudiation/fork event (see [AC-1]) so an honest operator can disclose a legitimate re-anchor without it being indistinguishable from an attack.
- Until the above ships, correct README limitation 4: the current property is "an entry shown to you is consistent with a root the operator published", not "an entry wasn't altered after commitment".

---

## [AC-3] Verification is performed by, and only by, the party being audited — separation of duties collapses to one key

**Severity**: Medium
**Category**: evm-audit-access-control
**Location**: `packages/cli/src/cli.ts:468-480` (`verifyEntries`); `packages/core/src/audit/anchor.ts:92-95` (`operatorAddress()`)
**Description**: `agentctl audit --verify` refuses to run without `ANCHOR_COMMITTER_KEY` (cli.ts:469-473) and derives the operator address from that private key (`anchor.operatorAddress()`, cli.ts:480 -> anchor.ts:92-95). The committer key is a _write_ credential; verification needs only the operator's public address. Requiring the private key means:

- An independent auditor, a counterparty, or a regulator cannot run the verification at all without being handed the operator's signing key — which would let them forge commits. The verification tool is structurally unusable by anyone except the operator, i.e. by exactly the party whose word the anchor exists to replace.
- There is no mechanism for a verifier to learn the correct operator address independently. The contract has no registry, no enumeration, no deploy-time record. The address is discovered by asking the operator, which is the same circularity the anchor is supposed to break.

Combined with [AC-2], every role in the trust model — producer, committer, index-recorder, verifier — is the same key. This is the checklist's _"When all agents are the same person"_ item in its purest form, and it is a trust-model violation rather than a code defect, hence Medium.

A related smaller point: nothing on chain binds an operator address to a real-world identity, so `verifyEntry(someAddress, ...)` returning `true` proves only "_whoever controls someAddress_ published a root containing this leaf". Printing that as "verified on-chain" (cli.ts:493) overstates it.

**Proof of Concept**:

```
An auditor is given: the deployed AUDIT_ANCHOR_ADDRESS, the operator's address,
and the SQLite export. They cannot run `agentctl audit --verify`:

  cli.ts:470   if (!contractAddress || !committerKey) { ...return; }
               -> "(--verify needs AUDIT_ANCHOR_ADDRESS + ANCHOR_COMMITTER_KEY in env)"

To proceed they must either (a) be given the private key — which grants them
commitBatch authority over the operator's identity — or (b) reimplement the
verifier themselves. Option (a) means the audit credential and the forge
credential are the same secret.
```

**Recommendation**:

- Add `--operator <address>` to `agentctl audit --verify` and require the private key only for `flush`/commit paths. Verification is a `readContract` call; `AuditAnchorClient.verifyEntry`/`getBatch`/`getBatchCount` already need no signer (they use `makePublicClient`) — only `operatorAddress()` forces the key in.
- Ship a read-only verification entry point (`agentctl audit --verify --operator 0x... --db exported.sqlite`) that a third party can run against an export plus a public RPC, with no secrets.
- Record the canonical operator on chain at deploy time or via a self-scoped `registerOperator(string calldata identity)` emitting an event, so "which address is this operator" has an on-chain answer rather than an out-of-band one.
- Soften the CLI wording: `verified on-chain` should read as `matches root published by 0xABC...` so the output does not imply more than inclusion under a self-asserted identity.

---

## [AC-4] `entryCount` is caller-supplied, uncommitted, and never checked — the only completeness signal is unauthenticated

**Severity**: Medium
**Category**: evm-audit-access-control
**Location**: `commitBatch()` / `AuditAnchor.sol:34-39`, `Batch.entryCount` / `AuditAnchor.sol:20`
**Description**: `entryCount` is written to storage and emitted, and that is all that ever happens to it. It is not validated against the proof arity in `verifyEntry`, not bound into the Merkle root (the root is over leaves only — `merkle.ts:48`), and not constrained relative to the previous batch. No caller-supplied value in this contract is validated at all.

This matters more than a cosmetic unused field, because `entryCount` is the _only_ piece of data in the system that could support a completeness argument. A Merkle root proves inclusion; it cannot prove that nothing was excluded. A trustworthy count would at least let a verifier say "the chain says this batch had 5 entries and my store only produces 4 — something is missing". As written, the operator sets the count to whatever makes the story consistent: in the [AC-2] PoC, `commitBatch(R1, 4)` declares four entries because four is what the rewritten store contains.

`verifyEntries()` reads the batch via `getBatch()` (cli.ts:488) and uses only `batch.root`; the returned `entryCount` (anchor.ts:137) is discarded. So even the unauthenticated signal that does exist is never consulted. Incorrect accounting on a field the product's guarantee leans on, hence Medium.

**Proof of Concept**:

```solidity
// Nothing rejects any of these:
anchor.commitBatch(root, 0);                 // a root over 5 leaves, declared as 0
anchor.commitBatch(root, type(uint256).max); // declared as 2^256-1
anchor.commitBatch(root, 4);                 // batch 1 "smaller" than batch 0's 5
```

```
And no consumer notices:
  cli.ts:488   const batch = await anchor.getBatch(operator, proof.batchIndex);
  cli.ts:490   const rootMatch = batch.root.toLowerCase() === proof.localRoot.toLowerCase();
               // batch.entryCount is fetched and thrown away.
```

Consequence: in the [AC-2] rewrite, a verifier who _did_ look at counts would see `(5, 4)` — suspicious — but the operator can equally commit `(5, 5)` by padding the rewritten batch with a synthetic entry, and nothing checks that the padded leaf corresponds to a real decision.

**Recommendation**:

- Bind the count into the commitment so it cannot be restated independently of the tree: commit `keccak256(abi.encode(merkleRoot, entryCount))`, or make the tree's leaf count structurally recoverable and check it in `verifyEntry`.
- `require(entryCount > 0)` at minimum — an empty batch is never a legitimate commit (`flush()` already returns early on `rows.length === 0`, logger.ts:113).
- Have `verifyEntries()` consume `batch.entryCount`: assert `store.entriesInBatch(i).length === onChain.entryCount` for every on-chain batch index `0..getBatchCount(operator)-1`, and report any batch the local store cannot fully reproduce. This is the missing completeness check and it costs one extra comparison per batch.
- Consider committing a canonical entry-ID set digest alongside the root so "which entries were in batch N" is itself anchored rather than inferred from a mutable `batch_index` column.

---

## [AC-5] `commitBatch` returns no index, forcing an unsafe read-after-write inference that breaks under the documented shared-key multi-writer deployment

**Severity**: Medium
**Category**: evm-audit-access-control
**Location**: `commitBatch()` / `AuditAnchor.sol:34-39`; `packages/core/src/audit/logger.ts:118-125`; `packages/core/src/audit/anchor.ts:114-123`
**Description**: `commitBatch` has `outputs: []`. The batch index exists only in the emitted event and implicitly as the array length. The client therefore infers it:

```ts
const txHash = await this.anchorClient.commit(root, rows.length); // logger.ts:118
const operator = this.anchorClient.operatorAddress();
const idx = (await this.anchorClient.getBatchCount(operator)) - 1; // logger.ts:121
await this.store.markBatched(
  rows.map((r) => r.id),
  idx,
); // logger.ts:122
```

This is a read-after-write across two separate RPC calls with no linkage to `txHash`. `commit()` does wait for the receipt (anchor.ts:85-87, correctly fixing an earlier off-by-one), but waiting for _your own_ receipt does not make `getBatchCount()` identify _your_ index — it only guarantees the count is at least your index + 1.

The contract's own design makes the safe alternative unavailable: because writes are keyed solely by `msg.sender`, two processes sharing one `ANCHOR_COMMITTER_KEY` are the _same_ operator and write into the _same_ array, yet neither can learn which slot it landed in. `store.ts` ships a Postgres backend explicitly "for multi-agent operators" (store.ts:11-14), i.e. the multi-writer configuration is a supported deployment, and nothing in the config prevents those writers from sharing one committer key — there is only one such env var.

The failure is silent and permanent for the affected entries: rows are stamped with a `batch_index` whose on-chain root belongs to a different batch, so `proofFor()` rebuilds a tree that will never match `getBatch().root`, and `--verify` reports MISMATCH forever with no way to recover the correct mapping (the correct index is knowable only from the `BatchCommitted` log, which nothing reads).

**Proof of Concept**:

```
Two guard processes P1, P2, same ANCHOR_COMMITTER_KEY (address A), shared Postgres store.

t0  P1.flush(): unbatched() -> rows_A (ids 1..5)
t1  P2.flush(): unbatched() -> rows_B (ids 1..8; 1..5 still NULL, P1 hasn't marked yet)
t2  P1 commit(R_A, 5) mined  -> batches[A][0] = R_A
t3  P2 commit(R_B, 8) mined  -> batches[A][1] = R_B
t4  P2 getBatchCount(A) = 2  -> idx 1 -> markBatched(ids 1..8, 1)   // correct for P2
t5  P1 getBatchCount(A) = 2  -> idx 1 -> markBatched(ids 1..5, 1)   // WRONG: R_A is at 0
t6  proofFor(id 1): entriesInBatch(1) -> ids 1..8 -> localRoot = R_B
    batches[A][0] is now orphaned: no local row references it, and ids 1..5 are
    double-anchored under two contradictory roots.

Reorder t2/t3 (equally possible — two clients racing on one nonce sequence) and
P1 stamps index 1 for a root that sits at index 0 with a disjoint leaf set: every
one of ids 1..5 reports MISMATCH permanently.
```

The single-writer case is safe today only because no other address can push into `batches[A]` — a property of _key custody_, not of the contract, and the contract offers nothing to detect when that assumption breaks.

**Recommendation**:

- Return the index from the contract — a one-line change that removes the entire class:
  ```solidity
  function commitBatch(bytes32 merkleRoot, uint256 entryCount) external returns (uint256 batchIndex) {
      batchIndex = batches[msg.sender].length;
      batches[msg.sender].push(Batch(merkleRoot, block.timestamp, entryCount));
      emit BatchCommitted(msg.sender, batchIndex, merkleRoot, entryCount);
  }
  ```
  A `returns` value is not readable from an EOA-sent transaction, so pair it with the client fix below; the return value makes the contract composable for contract-operators (see [AC-1]'s Safe recommendation).
- Fix the client regardless: parse `BatchCommitted` from the mined receipt's logs (`commit()` already has the receipt in hand, anchor.ts:85-87) and return `batchIndex` from `commit()` instead of calling `getBatchCount()`. That binds the index to _this_ transaction.
- Guard the deployment: either forbid sharing one committer key across writers (document it and add a startup lock), or give each writer its own key — which is only safe once verifiers enumerate multiple operator addresses.
- Add the reconciliation check from [AC-4] so an orphaned on-chain batch (index 0 above, referenced by no local row) is reported rather than ignored.

---

## [AC-6] `commitBatch` validates no input; a zero root makes `verifyEntry` return true for a zero leaf

**Severity**: Low
**Category**: evm-audit-access-control
**Location**: `commitBatch()` / `AuditAnchor.sol:34-39`, `verifyEntry()` / `AuditAnchor.sol:42-56`
**Description**: There is no `require` anywhere in the contract. `merkleRoot == bytes32(0)` and `entryCount == 0` are both accepted. Because `verifyEntry` starts with `computed = leaf` and an empty `proof` leaves it unchanged, a batch committed with a zero root returns `true` for `leaf == bytes32(0), proof == []`. More generally, any committed root trivially "verifies" itself as a single leaf with an empty proof — correct behaviour for a genuine single-entry `StandardMerkleTree` (the test at `contracts/test/AuditAnchor.t.sol:24-31` relies on it), but it means a root value can never be distinguished from a leaf value by the contract.

`MerkleAuditBatch.root()` returns `ZERO_ROOT` for an empty batch (`merkle.ts:16,54-57`). `flush()` currently cannot reach it (`logger.ts:113` returns early on zero rows), so this is a latent hazard rather than a live bug, but the contract accepts the exact value the off-chain code designates as "nothing here".

Impact is limited: the batch is self-scoped, so a junk commit pollutes only the committer's own array, and a verifier following the intended flow supplies real leaves. Rated Low as a missing-validation / latent-bug issue.

Noted and _not_ rated separately: per-operator array growth is unbounded, but each `push` is paid for by the caller and lands only in that caller's own slot, so there is no cross-operator griefing or DoS vector.

**Proof of Concept**:

```solidity
function testZeroRootVerifiesZeroLeaf() public {
    anchor.commitBatch(bytes32(0), 0);                 // accepted
    bytes32[] memory proof = new bytes32[](0);
    assertTrue(anchor.verifyEntry(address(this), 0, bytes32(0), proof)); // true
}
```

**Recommendation**:

```solidity
require(merkleRoot != bytes32(0), "empty root");
require(entryCount > 0, "empty batch");
```

and, in `verifyEntry`, reject the degenerate read explicitly:

```solidity
bytes32 root = batches[operator][batchIndex].merkleRoot;
if (root == bytes32(0) || leaf == bytes32(0)) return false;
```

Also remove the `ZERO_ROOT` fallback in `merkle.ts:54-57` in favour of throwing, so "empty batch" can never be silently converted into a committable value.

---

## [AC-7] `verifyEntry` reverts instead of returning false for an unknown batch index

**Severity**: Low
**Category**: evm-audit-access-control
**Location**: `verifyEntry()` / `AuditAnchor.sol:48`
**Description**: `batches[operator][batchIndex]` on an out-of-range index reverts with `Panic(0x32)` (array out-of-bounds) rather than returning `false`. The signature promises a boolean verdict and callers reasonably treat it as total. `AuditAnchorClient.verifyEntry` (anchor.ts:98-111) does not catch, so a stale or tampered local `batch_index` — exactly the field [AC-2] and [AC-5] show is untrustworthy — turns `agentctl audit --verify` into an unhandled rejection that aborts the whole loop at the first bad row, rather than printing MISMATCH and continuing. That converts a tamper signal into a crash, which is the less informative outcome. `getBatch()` (anchor.ts:126-138) has the same exposure and is called first (cli.ts:488).

**Proof of Concept**:

```
sqlite3 agentctl.sqlite "UPDATE audit_entries SET batch_index = 99 WHERE id='e1';"
agentctl audit --verify
  -> proofFor(e1) succeeds locally (the client has no bounds knowledge off-chain)
  -> anchor.getBatch(operator, 99) -> ContractFunctionExecutionError: Panic 0x32
  -> the for-loop at cli.ts:482 throws; entries e2.. are never checked at all.
```

**Recommendation**:

```solidity
if (batchIndex >= batches[operator].length) return false;
```

and wrap the per-entry body of `verifyEntries()` (cli.ts:482-495) in try/catch so one bad row prints `MISMATCH (no such batch)` and the loop continues — a verification tool should never stop reporting because it found something wrong.

---

## [AC-8] Deploy script conflates the deployer with the operator, and no canonical operator is recorded on chain

**Severity**: Low
**Category**: evm-audit-access-control
**Location**: `contracts/script/Deploy.s.sol:13-19`; `.env.example:41-44`
**Description**: `Deploy.s.sol` broadcasts with `vm.envUint("ANCHOR_COMMITTER_KEY")` — the same key the running agent uses to commit roots (`.env.example:44`, `logger.ts:64`). Deployment authority and operating authority are therefore the same secret, and that secret is documented as a hot, environment-resident "testnet key only" value (`anchor.ts:55`). The constructor sets no state and grants no roles, so a wrong deployment cannot leave the contract in a _vulnerable_ state — but it does mean the key that must be present on every agent host is also the key used in the deploy/CI environment, widening the exposure surface for [AC-1].

Separately, the deployment records nothing about who the operator is. `AuditAnchor` has no constructor, no `deployer` field, no `Deployed` event. There is no on-chain artifact tying the contract to an intended operator address, so the verifier's notion of "the operator" (see [AC-3]) has no anchor at all.

Checklist mapping: _"Deploy scripts not included in audit scope"_ — reviewed; no privileged initial state is set (correct), but the key reuse and the missing operator record are the two deployment-time observations worth acting on.

**Proof of Concept**:

```
Deploy.s.sol:14   uint256 pk = vm.envUint("ANCHOR_COMMITTER_KEY");
.env.example:44   ANCHOR_COMMITTER_KEY=0x...   # also read by AuditLogger at runtime
logger.ts:64      if (anchor?.committerKey) { new AuditAnchorClient({ committerKey, ... }) }

-> one secret is present in: the deploy/CI environment, every agent host's .env,
   and every agent process's memory. Any one of those leaking yields permanent,
   unrevocable commit authority (AC-1).
```

**Recommendation**:

- Use a distinct `DEPLOYER_KEY` in `Deploy.s.sol`. The deployer needs no ongoing authority over this contract (there is none to have), so it should be a throwaway or hardware-backed key, never the runtime committer.
- Emit deployment provenance and an operator declaration, e.g. a self-scoped `registerOperator(string calldata label)` with an event, so verifiers can resolve an operator address from chain data plus one out-of-band label rather than from an address handed over by the operator.
- Update `.env.example` to state that `ANCHOR_COMMITTER_KEY` grants unrevocable, permanent write authority over the operator's audit history and that its compromise cannot be remediated (see [AC-1]).

---

## [AC-9] Absence of owner, pause, and upgrade is correct for this contract; the missing governance is at the identity layer

**Severity**: Info
**Category**: evm-audit-access-control
**Location**: `AuditAnchor.sol` (whole file)
**Description**: On whether the absence of admin functions is correct: for the _storage_ contract it is, and adding admin functions here would be a defect rather than a fix.

- An **owner** would create an authority over an append-only public record whose entire value is that no one can edit it. There is no legitimate owner action: no parameter to tune, no fee, no oracle, no allowlist.
- A **pause** would let a privileged party block operators from anchoring. In an audit system the ability to stop the record being written is itself an attack, and would hand a censor exactly the capability the anchor exists to deny.
- **Upgradeability** would be the worst of the three: an upgradeable anchor means historical roots can be reinterpreted or the verification logic swapped, so a proof that verified yesterday need not verify tomorrow. Immutability is a feature here, and the contract is correctly non-upgradeable with no constructor, no initializer, and no proxy.

The real governance gap is one layer up and is covered by [AC-1] and [AC-3]: identity lifecycle (rotation, retirement, repudiation, successor declaration) and operator discovery. Those are legitimately needed, and every one of them can be added _without_ a privileged role — each can be self-scoped to `msg.sender`, preserving the permissionless property while giving verifiers the state transitions they need to reason about an operator over time. "Permissionless and self-scoped" is the right frame; "self-scoped and stateless" is the part that does not hold up.

**Proof of Concept**: N/A — design evaluation, no exploit.

**Recommendation**: Keep the contract ownerless, unpausable, and immutable. Add only `msg.sender`-scoped identity-lifecycle functions and events as described in [AC-1] and [AC-3]. If a mutable registry mapping operator addresses to human-readable identities is wanted, deploy it as a _separate_ contract so the anchor itself stays immutable and a compromise of the registry cannot touch committed roots.

---

## Cleared

Checklist items walked and found not applicable, or applicable and clean, with the reason.

**Centralization Risks**

- _Admin can perform token transfers on behalf of users_ — **N/A, cleared.** The contract holds no tokens and no ETH, has no `payable` function, makes no external calls, and contains no `transfer`/`transferFrom`/`call`. There is no rescue or emergency-withdraw function and nothing to rescue.
- _Instant parameter changes without timelock_ — **N/A, cleared.** There are no parameters. No setters, no configurable addresses, no rates, no oracle. The only state written is the caller's own batch array.
- _Total upgradeability_ — **Cleared as correct.** No proxy, no `_authorizeUpgrade`, no `delegatecall`, no constructor, no initializer. The contract is immutable. See [AC-9] for why that is the right choice here rather than a gap.
- _Pausing that blocks critical user operations_ — **N/A, cleared.** No pause mechanism exists, so there is no asymmetric-pause hazard. See [AC-9] for why adding one would be harmful.
- _Corrupted owner can destroy the protocol_ — **Not cleared.** There is no owner, but the analogous single point of failure exists at the committer-key level. Reported as **[AC-1]**.

**Privilege Escalation**

- _Missing access controls on sensitive functions_ — **Cleared for the intended design, with a caveat.** `commitBatch` is deliberately permissionless and is genuinely self-scoped: the write target is `batches[msg.sender]`, not derivable from any argument, so no caller can write into another operator's array. `verifyEntry` and `getBatchCount` are `view`. There is no `mint`/`burn`/`setOracle`-class function. The caveat is that "permissionless" was implemented as "unvalidated" — no input checks at all, reported as **[AC-6]**.
- _Two-step ownership transfer not implemented_ — **N/A, cleared.** No `Ownable`, no ownership to transfer. The analogous problem — identity handover without a two-step, observable transition — is the rotation half of **[AC-1]**.
- _Functions operating on other users assume msg.sender is the user_ — **Cleared.** This is the item the design gets right. `commitBatch` takes no `operator` parameter; the write key is `msg.sender` only. `verifyEntry` and `getBatchCount` do take an `operator` parameter, but both are `view` and expose only data that address published itself, so a caller-supplied address grants no authority over another operator. `contracts/test/AuditAnchor.t.sol:49-54` tests exactly this scoping and the test is correct.
- _Whitelist bypass via proxy tokens_ — **N/A, cleared.** No whitelist, no allowlist, no token addresses, no address-based access decisions of any kind.

**Role Management**

- _Roles granted in constructor but not documented_ — **N/A as written, cleared.** There is no constructor and no `_grantRole`. The inverse observation (the effective role is undocumented because no role system exists) is folded into **[AC-1]**.
- _No cap on privileged role count_ — **N/A, cleared.** No roles, so nothing to cap. Any address can become an "operator" by committing, but each is isolated to its own array and confers no authority over anyone else, so unbounded operator count is not a dilution risk. Storage growth is self-funded by the committing address.
- _Renounce ownership can brick contract_ — **N/A, cleared.** No `renounceOwnership`, and no owner-only operation the contract depends on, so there is no brick path via renunciation.

**Initialization & Deployment**

- _Initializer callable by anyone on the implementation_ — **N/A, cleared.** Not an upgradeable contract; no `initialize`, no need for `_disableInitializers`. The contract has no initialization state whatsoever.
- _Deploy scripts in scope_ — **Reviewed, partially cleared.** `Deploy.s.sol` sets no privileged state, assigns no roles, and passes no constructor parameters, so no misconfiguration can leave the contract vulnerable — that part is clean. The key-reuse and missing-operator-record observations are reported as **[AC-8]**.

**Multi-Agent Access**

- _When all agents are the same person_ — **Not cleared.** This is the domain's central finding here: producer, committer, index-recorder and verifier are one key and one process. Reported as **[AC-2]** (equivocation) and **[AC-3]** (verifier identity), with the shared-key multi-writer variant as **[AC-5]**.

**Out of scope for this domain, noted for other reviewers**

- Merkle verification semantics (second-preimage resistance of the leaf encoding, proof malleability under sorted-pair hashing, empty-proof acceptance). The off-chain side uses `@openzeppelin/merkle-tree`'s `StandardMerkleTree`, which double-hashes `abi.encode`d leaves (`merkle.ts:48`), so an internal node cannot be passed off as a leaf — the encoding choice looks sound. Depth/arity and duplicate-leaf handling were not analysed here; they belong to the merkle/cryptography domain.
- Leaf field coverage. `entryToLeaf` (`merkle.ts:22-30`) commits `agentId`, `timestamp`, `recipient`, `verdict` and `entryHash` but not `resourceUrl` or the settlement `txHash`; `hashEntry` (`logger.ts:19-32`) omits the settlement entirely. Disclosed as README limitation 9; a data-completeness question rather than an access-control one.
- Gas/DoS on `verifyEntry` proof length, and calldata cost of large batches.
