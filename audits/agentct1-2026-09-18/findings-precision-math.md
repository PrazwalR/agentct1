# Precision & Math — AuditAnchor.sol

**Domain**: `evm-audit-precision-math`
**Target**: `/Users/prazw/Desktop/Web3/agentct1/contracts/src/AuditAnchor.sol`
**Off-chain counterpart cross-checked**: `packages/core/src/audit/merkle.ts`, `.../audit/logger.ts`, `.../audit/anchor.ts`
**Date**: 2026-09-18

## Summary

`AuditAnchor` performs essentially no arithmetic: one subtraction, one loop counter, no
division, no multiplication, no fixed-point scaling, no decimals, no fees, no downcasts.
The large majority of this checklist is genuinely **not applicable** — see the
"Cleared / Not Applicable" section, which is the main honest result of this pass.

The two items that required real work were the **encoding compatibility** with
`@openzeppelin/merkle-tree` and the **domain separation** of the leaf input. Compatibility
is **confirmed byte-for-byte by executed test vectors**. Domain separation is where the one
substantive finding lives.

All claims below were verified empirically, not by inspection: real `StandardMerkleTree`
roots/leaves/proofs were generated with the repo's own `@openzeppelin/merkle-tree@1.0.8`
and replayed through a compiled copy of `AuditAnchor.sol` under Foundry (solc 0.8.24).
9/9 assertions passed, including two fuzz properties at 256 runs each. No repo file was modified.

| ID   | Severity | Title                                                                                         |
| ---- | -------- | --------------------------------------------------------------------------------------------- |
| PM-1 | Medium   | `verifyEntry` accepts any `bytes32` as a leaf — internal tree nodes verify as audit entries   |
| PM-2 | Low      | No bound on `proof.length`; zero-root and root-as-leaf both verify trivially                  |
| PM-3 | Low      | `entryCount` is unvalidated, unused, and unbound to the committed tree                        |
| PM-4 | Info     | `Batch` wastes a storage slot — 21,752 gas/commit measured; downcast hazard if packed naively |
| PM-5 | Info     | `batches[msg.sender].length - 1` cannot underflow (verified)                                  |
| PM-6 | Info     | Loop counter cannot overflow; `unchecked` is safe but not worth it (178 gas measured)         |
| PM-7 | Low      | Off-chain batch index derived by unchecked JS subtraction instead of the emitted `batchIndex` |

---

## [PM-1] `verifyEntry` accepts any `bytes32` as a leaf — internal tree nodes verify as audit entries

**Severity**: Medium
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.verifyEntry()` — `contracts/src/AuditAnchor.sol:42-56`
**Description**:
`verifyEntry` takes the leaf **already hashed** and processes it with the same commutative
hash used for internal nodes. It therefore cannot distinguish a leaf from an internal node.
Any node of the committed tree — including every intermediate node — can be passed as `leaf`
with the (shorter) proof from that node to the root, and the function returns `true`.

The standard OpenZeppelin mitigation for this second-preimage class is the **double leaf
hash**: `standardLeafHash = keccak256(keccak256(abi.encode(types, value)))`, so a 32-byte
internal node can never be the image of a valid value encoding. That mitigation is present
in the off-chain code (`merkle.ts` uses `tree.leafHash(value)`), but it lives **entirely
off-chain**. The contract's ABI surface takes an opaque `bytes32`, so the on-chain
"anyone can verify" guarantee advertised in the NatSpec ("Anyone can later verify a specific
audit entry was included and unaltered") does not actually hold against a leaf supplied by
an untrusted party — `true` means "this hash is _somewhere_ in the tree", not "this is an
audit entry".

This does not break the shipped CLI path: `packages/cli/src/cli.ts:489` derives the leaf
itself via `log.proofFor()` -> `batch.leafAt()` and additionally asserts `rootMatch` locally.
The exposure is to any _third-party_ verifier — precisely the audience the anchor exists
for — that is handed a `(leaf, proof)` pair by the operator and calls `verifyEntry` directly.

**Proof of Concept**:
Real `StandardMerkleTree.of(values, ["string","uint256","address","uint8","bytes32"])`
over 8 values, root `0x5256e6ae57f1034e5dd4650e939b217d08317a814a877b90052001bb5ae6a62e`.
`tree[4] = 0x44c5b9172740b44ba40b8b183c9d17fe8bd446fcbf8a3de1880d730c3e70d4cb` is an
**internal node**, never a leaf, never an audit entry:

```solidity
anchor.commitBatch(0x5256e6ae...a62e, 8);
bytes32 fakeLeaf = 0x44c5b9172740b44ba40b8b183c9d17fe8bd446fcbf8a3de1880d730c3e70d4cb; // tree[4]
bytes32[] memory p = new bytes32[](2);
p[0] = 0x8492559de17687739a1544896d4c32b71edeb26eede0141689b2cd2db40c7eee; // tree[3]
p[1] = 0xc585f56d2618bd98d942740a395734e5e992aa1363716c26b37dd1c8a79f9e0f; // tree[2]
assertTrue(anchor.verifyEntry(address(this), 0, fakeLeaf, p));  // PASSES
```

Executed: `[PASS] testSecondPreimageInternalNode() (gas: 103055)`.

Related, same root cause (both executed and passing):

- `verifyEntry(op, i, root, new bytes32[](0))` -> `true` (the root proves itself).
- Proof malleability: because pairing is commutative, the `(leaf, proof)` pair is not a
  canonical encoding — fuzzed at 256 runs, arbitrary sibling values verify against the root
  they were constructed from regardless of side. This is inherent to sorted-pair hashing and
  is why a verifier must never treat the pair as an identifier.

**Recommendation**:
Make the contract, not the caller, responsible for domain separation. Either:

1. **Preferred** — have `verifyEntry` accept the audit entry's fields and compute the leaf
   itself, exactly reproducing `standardLeafHash`:
   ```solidity
   bytes32 leaf = keccak256(bytes.concat(
       keccak256(abi.encode(agentId, timestamp, recipient, verdict, entryHash))
   ));
   ```
   This is byte-identical to `@openzeppelin/merkle-tree`'s leaf hash and makes an internal
   node unreachable as a leaf. Keep the current raw-leaf function only as an internal helper.
2. If the opaque-leaf ABI must stay for gas/flexibility, rename it to something that does not
   promise entry semantics (e.g. `verifyNodeInclusion`) and document loudly that callers MUST
   compute the leaf hash themselves from entry data.

Additionally consider bounding `proof.length` against the stored `entryCount` (see PM-2/PM-3),
which raises the cost of the truncated-proof variant.

---

## [PM-2] No bound on `proof.length`; zero-root and root-as-leaf both verify trivially

**Severity**: Low
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.verifyEntry()` — `contracts/src/AuditAnchor.sol:50`; `AuditAnchor.commitBatch()` — `:34`
**Description**:
Two boundary cases in the proof loop are unguarded:

1. **`proof.length == 0`** short-circuits the loop, so the function degenerates to
   `leaf == root`. Legitimate for a single-leaf tree (where `root == leafHash`), but it also
   means the publicly readable root is always "provable" as an entry of its own batch.
2. **`merkleRoot == bytes32(0)`** is accepted by `commitBatch` with no validation. The
   off-chain `merkle.ts:16` defines exactly such a value — `ZERO_ROOT` is returned by `root()`
   for an empty batch. Combined with (1), a batch committed with a zero root verifies
   `leaf = bytes32(0)` with an empty proof. `logger.flush()` currently returns early on
   `rows.length === 0` so the shipped path never commits `ZERO_ROOT`, but nothing in the
   contract enforces that.

There is also no upper bound tying `proof.length` to the committed `entryCount`: a legitimate
proof for an `n`-leaf `StandardMerkleTree` has length `floor(log2(n))` or `ceil(log2(n))`,
but the loop will happily process an arbitrarily long or arbitrarily short proof. This is the
checklist's "off-by-one / boundary comparison" item applied to proof depth.

**Proof of Concept**: both executed and passing.

```
[PASS] testZeroRootAcceptsZeroLeaf()   // commitBatch(bytes32(0), 0); verifyEntry(..., bytes32(0), []) == true
[PASS] testRootIsProvableAsLeaf()      // verifyEntry(..., storedRoot, []) == true
```

**Recommendation**:

- In `commitBatch`, `require(merkleRoot != bytes32(0), "empty root")`.
- In `verifyEntry`, reject the degenerate case and sanity-bound the depth, e.g.
  `require(proof.length > 0 || entryCount == 1)` and `require(proof.length <= _ceilLog2(entryCount))`
  using the stored `entryCount`. This is cheap (`view` function, no storage cost) and materially
  narrows PM-1's truncated-proof variant. It is defence-in-depth, not a substitute for PM-1's
  fix — the OZ tree is complete but not perfectly balanced, so the bound is a range, not an equality.

---

## [PM-3] `entryCount` is unvalidated, unused, and unbound to the committed tree

**Severity**: Low
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.commitBatch()` — `contracts/src/AuditAnchor.sol:34-39`
**Description**:
`entryCount` is a caller-supplied `uint256` that is stored, indexed into an event, and then
never read by any contract logic. It is the only on-chain statement about how many audit
entries a root covers, and nothing constrains it: `0` is accepted alongside a non-zero root,
and `type(uint256).max` is accepted alongside a one-leaf tree. A verifier cannot use it to
detect that an operator omitted entries from a batch, which is the only thing it could
plausibly be for.

This is not an exploit — the operator is the party being audited and self-reports both the
root and the count — but it is _accounting that reads as a guarantee and is not one_. Callers
(and the NatSpec) should not treat it as a bound. Flagged because the checklist's "incorrect
accounting / value that appears to constrain but does not" category applies directly, and
because PM-2's recommended depth check would give `entryCount` an actual consistency role.

**Proof of Concept**: no test needed — `entryCount` appears only at `AuditAnchor.sol:20`
(struct field), `:36` (write), and `:38` (event). It is read by no function.
`grep -n entryCount contracts/src/AuditAnchor.sol` confirms three sites, zero reads.

**Recommendation**:
`require(entryCount > 0)` at minimum, and give it teeth by using it in the `verifyEntry` depth
bound from PM-2. Otherwise document it explicitly as unverified operator-supplied metadata so
no downstream consumer builds a completeness check on it.

---

## [PM-4] `Batch` wastes a storage slot — 21,752 gas/commit measured; downcast hazard if packed naively

**Severity**: Info
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.Batch` — `contracts/src/AuditAnchor.sol:17-21`
**Description**:
`Batch` is `bytes32 + uint256 + uint256` = 3 full slots, so each `commitBatch` pays three cold
`SSTORE`s. `merkleRoot` needs its own slot, but `timestamp` and `entryCount` fit comfortably in
one shared slot, taking the struct to 2 slots.

Raised as **Info, not a recommendation to change**, because the safe-width analysis is
asymmetric and the current code has _zero_ downcast risk — which is the checklist-relevant
point. If the team does pack, the two fields are not equally safe:

- `uint64 timestamp = uint64(block.timestamp)` — **safe**. `block.timestamp` cannot reach
  `2^64` (year ~584 billion). Even `uint48` is safe past year 8.9 million.
- `uint64 entryCount` — **not safe without validation**. `entryCount` is caller-supplied and
  unvalidated (PM-3). A naked `uint64(entryCount)` is exactly the checklist's "downcast overflow
  silently truncates" item: `commitBatch(root, 2**64)` would store `0` with no revert.

**Proof of Concept**: measured under Foundry, same solc settings as the repo's `foundry.toml`
(0.8.24, optimizer on):

```
commitBatch current (3 slots): 92731
commitBatch packed  (2 slots): 70979
saving:                        21752
```

**Recommendation**:
Optional. If packing, use `uint64 timestamp` and `uint64 entryCount`, and guard the count with
`require(entryCount <= type(uint64).max)` or OpenZeppelin `SafeCast.toUint64` — never a bare
cast. Combine with the `entryCount > 0` check from PM-3 so the field is validated in one place.

---

## [PM-5] `batches[msg.sender].length - 1` cannot underflow (verified)

**Severity**: Info
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.commitBatch()` — `contracts/src/AuditAnchor.sol:38`
**Description**:
Explicitly checked as requested. **The subtraction is unreachable at `length == 0`.** The `push`
on lines 35-37 executes before the `emit` on line 38, so `length >= 1` at every point where the
expression is evaluated. There is no early-return, no `try`, no reentrancy path (no external
calls in `commitBatch`), and no other writer to `batches[msg.sender]` between the two statements.
The invariant is structural, not incidental.

Had it been reachable: under Solidity `^0.8.24` the subtraction is **checked**, so `0 - 1` reverts
with `Panic(0x11)` (arithmetic underflow). It would **not** wrap to `type(uint256).max` — wrapping
requires an `unchecked` block, and there is none in this contract. So the worst case is a revert
(a failed commit, no griefing beyond the caller's own tx), never a corrupt `batchIndex` in the
event log. This is the correct 0.8.x behaviour and no `unchecked` should be added here.

Array-length overflow at the other end is also unreachable: Solidity's `push` reverts with
`Panic(0x41)` before a storage array length could wrap, and reaching `2^64` batches is not
physically possible.

**Proof of Concept**:

```
[PASS] testEmitIndexNeverUnderflows() (gas: 372361)
// 5 sequential commitBatch calls; getBatchCount == i+1 after each. No revert, indices 0..4.
```

**Recommendation**: None. Leave as-is. Do **not** wrap in `unchecked` — the saving is a handful
of gas and it would remove the (unreachable but free) backstop.

---

## [PM-6] Loop counter cannot overflow; `unchecked` is safe but not worth it

**Severity**: Info
**Category**: evm-audit-precision-math
**Location**: `AuditAnchor.verifyEntry()` — `contracts/src/AuditAnchor.sol:50`
**Description**:
`for (uint256 i = 0; i < proof.length; i++)`. `i` is bounded above by `proof.length`, which is
bounded by calldata size and therefore by the block gas limit — roughly `10^5` elements in the
most extreme case, versus the `2^256` needed to overflow. `unchecked { ++i; }` is **provably safe**
here by the checklist's own standard ("every unchecked block must have a proof that overflow is
impossible").

It is nonetheless **not recommended**, on cost-benefit grounds rather than safety. `verifyEntry`
is `view`: the normal call path is `eth_call` (free), and on-chain callers pay the two `keccak256`
hashes per iteration, which dominate the counter check by two orders of magnitude.

**Proof of Concept**: measured, 20-element proof, identical loop body:

```
checked loop (20):  20421
unchecked loop(20): 20243
saving:               178   // ~8.9 gas/iteration, ~0.9% of loop cost
```

**Recommendation**: None. Keep the checked loop — readability is worth more than 178 gas on a
`view` function. If it is ever changed, `unchecked { ++i; }` is the correct form and the
justification above should go in a comment next to it, per the checklist's `unchecked`
documentation requirement.

---

## [PM-7] Off-chain batch index derived by unchecked JS subtraction instead of the emitted `batchIndex`

**Severity**: Low
**Category**: evm-audit-precision-math
**Location**: `packages/core/src/audit/logger.ts:119-123` (`AuditLogger.flush()`), with `packages/core/src/audit/anchor.ts:80-88`, `:114-122`
**Description**:
The off-chain mirror of PM-5's subtraction is **not** protected by checked arithmetic:

```ts
const idx = (await this.anchorClient.getBatchCount(operator)) - 1;
await this.store.markBatched(
  rows.map((r) => r.id),
  idx,
);
```

JavaScript has no underflow trap, so a stale or unexpected read yields `idx = -1` (or an index
pointing at the _previous_ batch) and `markBatched` persists it silently. Because `proofFor()`
later rebuilds the batch from `store.entriesInBatch(batchIndex)`, a wrong index means those
entries can never produce a verifying proof again — a permanent, silent loss of the anchoring
guarantee for that batch, with no error surfaced.

The primary cause is already fixed: `anchor.ts:82-87` waits for the transaction receipt before
the read, with a comment naming this exact off-by-one. Two residual gaps remain:

1. `waitForTransactionReceipt` **resolves on a reverted transaction** — it does not throw on
   `status: "reverted"`, and the result's `status` is never checked. A reverted `commitBatch`
   still proceeds to `markBatched` with the _previous_ batch's index (or `-1` on the first commit).
2. The read-back races with any other process holding the same committer key, and with a
   single-confirmation re-org.

Also noted, no impact today: `anchor.ts:114-122` narrows the `uint256` return through `Number(n)`,
which loses precision above `2^53`. Unreachable for a batch counter.

**Proof of Concept**: source-level; no on-chain PoC applies. The failure shape is exactly the one
the existing comment at `anchor.ts:82-85` describes, re-armed by a reverted or re-orged tx:
`getBatchCount()` returns `0` -> `idx === -1` -> `markBatched(ids, -1)` -> `entriesInBatch(-1)`
returns nothing -> `proofFor()` produces a proof against the wrong tree.

**Recommendation**:
Stop deriving the index by subtraction. The contract already emits it authoritatively —
`BatchCommitted(operator, batchIndex, merkleRoot, entryCount)` at `AuditAnchor.sol:38`. Have
`commit()` return the receipt, decode the `BatchCommitted` log with viem's `parseEventLogs`, and
return `batchIndex` from it. That is race-free, revert-proof, and removes the subtraction entirely.
At minimum, assert `receipt.status === "success"` and `idx >= 0` before `markBatched`.

---

## Byte-compatibility with `@openzeppelin/merkle-tree` — CONFIRMED

Verified by execution, not inspection, against the repo's installed
`@openzeppelin/merkle-tree@1.0.8` (`node_modules/.pnpm/@openzeppelin+merkle-tree@1.0.8/.../dist/`):

| Layer         | Library (JS)                                                                              | Contract (Solidity)                                                           | Match |
| ------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----- |
| Leaf hash     | `standardLeafHash = keccak256(keccak256(abi_encode(types, value)))` (`hashes.js`)         | supplied pre-hashed; `merkle.ts:63` passes `tree.leafHash(value)`             | yes   |
| Node hash     | `standardNodeHash(a,b) = keccak256(concat([a,b].sort(compare)))` (`hashes.js`)            | `a < b ? keccak256(abi.encodePacked(a,b)) : keccak256(abi.encodePacked(b,a))` | yes   |
| Ordering      | `compare(a,b) = BigInt(hex a) - BigInt(hex b)` (`bytes.js`) — unsigned big-endian 256-bit | `bytes32 <` compiles to EVM `LT` (unsigned) on the left-aligned word          | yes   |
| Proof walk    | `processProof = proof.reduce(nodeHash, leaf)` (`core.js`)                                 | the `for` loop at `:50-54`                                                    | yes   |
| Concatenation | `concatBytes` -> 64 raw bytes                                                             | `abi.encodePacked(bytes32,bytes32)` -> 64 raw bytes                           | yes   |

Specific points confirmed:

- **Unsigned lexicographic ordering is correct and intended.** `bytes32` comparison in Solidity is
  unsigned (`LT`, not `SLT`), byte-for-byte the same order as the JS library's `BigInt` comparison.
  Verified directly: `[PASS] testBytes32LtIsUnsigned()` asserts `bytes32(1) < bytes32(1 << 255)` —
  signed semantics would have flipped this. This is also exactly OZ Contracts'
  `Hashes.commutativeKeccak256` (`a < b ? _efficientKeccak256(a,b) : _efficientKeccak256(b,a)`),
  and therefore `MerkleProof.processProof`.
- **Tie case is equivalent.** `Array.prototype.sort` is stable, so `a == b` leaves order `[a,b]`;
  the contract's `a < b` is false and takes the `(b,a)` branch. Identical bytes, identical digest.
- **`abi.encodePacked(bytes32, bytes32)` has no packing-collision hazard.** Both operands are
  fixed-width, so `encodePacked` emits exactly 64 bytes with no length prefix and no padding, and
  the split point is unambiguous at offset 32. Verified by fuzz:
  `[PASS] testFuzzPackedEqualsRawConcat(bytes32,bytes32) (runs: 256)` asserts equality with
  `bytes.concat(lo, hi)` and `length == 64`. Byte-identical to OZ's assembly `_efficientKeccak256`
  (`mstore(0x00,a); mstore(0x20,b); keccak256(0x00,0x40)`) — the assembly form is a gas
  optimisation, not a semantic difference.
  **Contrast**: the collision hazard people associate with `encodePacked` requires _two or more
  variable-length_ operands (`encodePacked("a","bc") == encodePacked("ab","c")`). Not reachable
  here. Note the _leaf_ encoding uses non-packed `abi.encode` in the JS library, which is the
  correct choice given `LEAF_TYPES` contains a dynamic `string`.
- **End-to-end vectors pass.** Real trees built with the exact
  `["string","uint256","address","uint8","bytes32"]` encoding at n = 1, 2, 3, 5, 8, 9, then
  `(root, leafHash(values[i]), getProof(i))` replayed through the compiled contract:
  `[PASS] testOZVectorsN8()`, `[PASS] testOZVectorsN9Unbalanced()` (n=9 exercises the unbalanced
  case where sibling subtrees differ in depth and one proof has length 4 while others have length 3).
- **`leafAt(i)` / `proofAt(i)` index the same element — no mismatch.** This was the highest-risk
  suspected bug and it is **clean**. `StandardMerkleTree.of` defaults to `sortLeaves: true`
  (`options.js`), which reorders leaves by hash. But `MerkleTreeImpl.prepare` builds `indexedValues`
  in the _original_ insertion order and stores the sorted position as `treeIndex` per value
  (`merkletree.js`), and `getProof(n)` treats a numeric argument as an index into that
  original-order array. So `merkle.ts`'s `leafAt(i)` (its own insertion-order `values[i]`) and
  `proofAt(i)` (`tree.getProof(i)`) refer to the same entry. Confirmed by a
  `tree.verify(values[i], tree.getProof(i))` self-check across all 6 tree sizes, all passing.
- **Batch reconstruction order does not matter.** `logger.proofFor()` rebuilds the tree from
  `store.entriesInBatch()`, which need not return rows in the original `unbatched()` order. Safe:
  because `sortLeaves` is on, the root is invariant under permutation of the input values.

---

## Cleared / Not Applicable

The following checklist areas were walked and found to have **no applicable code**. This contract
has no division, no multiplication, no fixed-point arithmetic, no token decimals, no shares, no
fees, no oracles, no interest, no `unchecked`, no assembly, no signed integers, and no casts.

**Division before multiplication** — all four items N/A. Not a single `/` or `*` operator in the
contract. No `mulDiv`/`wmul`/`wdiv`/library math. No scaling factors, so no double-division-by-`1e18`.
No expression can round to zero because no expression divides.

**Rounding direction** — all three items N/A. No deposits, mints, withdrawals, redeems, shares, or
fees. Nothing rounds, so no rounding direction can favour the wrong party and no dust can be
extracted by looping. No inverse-fee conversion exists.

**Integer overflow/underflow** — five of six items N/A; one addressed.

- `unchecked` blocks: **none exist** in the contract. Nothing to audit.
- Downcast overflow: **no casts at all** — no `uint128`/`uint64`/`uint32`, no `SafeCast` needed.
  Raised only as a forward-looking hazard in PM-4 if the struct is ever packed.
- Negative-to-unsigned cast: no `int` types anywhere; no absolute-value logic.
- Signed/unsigned mixed arithmetic: no signed types.
- Time-based arithmetic overflow: `block.timestamp` is **stored, never multiplied or subtracted**.
  No rate, no emission, no duration, no narrow time type.
- The one subtraction is covered in PM-5 (unreachable, and checked anyway).

**Decimal handling** — all four items N/A. No ERC-20, no oracle, no `decimals()` call, no price
computation, no `1e18`, no vault. The contract stores hashes and counts, which are dimensionless.
No 1-wei remainder can accumulate because nothing is divided.

**Accumulator & interest math** — all four items N/A. No rewards, no staking, no `rewardPerToken`,
no integrals, no `lastUpdate`, no fee shares, no accrual of any kind. Batches are append-only
records, never accumulated into a running total.

**Special values** — three of four items N/A.

- Assembly division by zero: **no assembly** in the contract.
- `type(uint256).max` as sentinel: not used. (`entryCount` accepting it is noted in PM-3 as a
  validation gap, not an overflow risk — it is stored, never added to anything.)
- Extreme weight ratios / exponentiation: no `**`, no weighted pool math.

**Precision loss patterns (Beirao/Tamjid)** — six of seven items N/A.

- Solidity time literals (`1 days` etc. being `uint24`): **no time literals used**.
- Rounding direction favouring protocol: no divisions in any path.
- Negative-to-uint assignment: covered by PM-5; the only subtraction is unreachable.
- `unchecked` needing justification: no `unchecked` blocks.
- Compounding precision loss across chained divisions: no divisions to chain.
- Off-by-one in comparison operators: the only comparisons are `i < proof.length` (standard,
  correct — iterates exactly `proof.length` times) and `computed < proof[i]` (verified above as
  the correct commutative-ordering predicate, where `<` vs `<=` is immaterial since the equal case
  produces identical bytes). The one genuine boundary gap — an unbounded `proof.length` — is PM-2.

**Dacian precision-loss set** — all seven items N/A. No `wmul`/`wdiv` chaining; no
value-proportional state updates that can round to zero; no mixing of 6- and 18-decimal quantities;
no scaling, hence no double-scaling and no `decimals()`-vs-`1e18` mismatch between modules; no
downcasts that could invalidate a prior `require`; no AMM or trade fees.

**Overall**: this contract is arithmetically trivial by design, and that is the right design for it.
Its integrity guarantee rests on hash-encoding correctness rather than numeric precision. The
encoding is correct and byte-compatible with the off-chain library (proven by executed vectors);
the one real weakness is domain separation at the `verifyEntry` boundary (PM-1), not math.

---

### Reproduction

Test vectors and the Foundry harness used for every `[PASS]` cited above were built in a
session scratchpad (`gen.cjs` generates the OZ vectors; `xcheck/` is a standalone Foundry
project containing a _copy_ of `AuditAnchor.sol`). No file in the repository was modified,
and nothing was written outside this findings file.
