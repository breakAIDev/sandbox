import fnmatch
import hashlib
import json
import os
import re
import requests
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional
from textwrap import dedent
from collections import defaultdict
from dataclasses import dataclass, field as dataclass_field
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

# PRIMARY_MODEL outputs structured JSON directly — it uses analyze_file() with all specialized
# prompts intact and thinking_budget=2048 for Tier-2 passes.  Reasoning capability is provided
# by thinking_budget (PRIMARY_MODEL), THINKING_MODEL (protocol classification + verifier), and
# ROUTER_MODEL (agentic deep-dive) rather than a 2-step text→JSON pipeline.
PRIMARY_MODEL = "qwen/qwen3.6-35b-a3b"

# Non-reasoning model: used for all non-discovery steps (merge, cluster, JSON structuring, related-file lookup).
JSON_MODEL = "qwen/qwen3-next-80b-a3b-instruct"

# High-standard models apply strict internal criteria and self-report fewer findings at lower
# confidence scores. Relax the post-processing confidence gate for their outputs so we don't
# silently discard valid findings that a lower-standard model would have reported at 0.75.
HIGH_STANDARD_MODELS = frozenset({"x-ai/grok-4.3"})

# Thinking model: used for protocol-model stage and verifier soft-rank.
# 235b-thinking has extended reasoning tokens for role classification and FP review.
THINKING_MODEL = "qwen/qwen3-235b-a22b-thinking-2507"

# Router model: high-capacity instruct model for agentic deep-dive.
# Better cross-file reasoning than qwen3.6 while still supporting tool-use.
ROUTER_MODEL = "qwen/qwen3-235b-a22b-2507"

# Provider routing per model — slugs verified from OpenRouter /api/v1/models/{id}/endpoints.
# ignore: providers with observed structural failures or speed too low to complete within timeout.
# order: preferred providers ranked by reliability + throughput from production run analysis.
_PROVIDER_ROUTING: dict[str, dict] = {
    THINKING_MODEL: {
        # deepinfra/atlas-cloud/novita: 32K max_completion cap — too low for Phase 4 large-context calls (7-8K input)
        # alibaba: max_completion=null + ignores budget_tokens → 82K+ output observed (Jun 2026 Phase 4, 8379 in → 82158 out)
        # wandb: only available provider with 262K max_completion that honors budget_tokens
        "ignore": ["deepinfra", "alibaba", "atlas-cloud", "novita"],
        "order": ["wandb"],
    },
    PRIMARY_MODEL: {
        # ambient: 25-46 tok/s; io-net: silent TCP failures; siliconflow: 17 tok/s; wandb: 32K hard cap
        # atlas-cloud: ignores max_tokens → 82K natural stop @ 234 tok/s (352s) — viable with 500s timeout
        # order removed — OR auto-balances across Parasail/AkashML/AtlasCloud/Alibaba/etc.
        "ignore": ["ambient", "io-net", "siliconflow", "wandb"],
    },
    JSON_MODEL: {
        # deepinfra: 16K max_completion cap; novita: 32K cap at same price as atlas-cloud (131K cap) — strictly worse
        # order removed — OR auto-balances across Parasail/AtlasCloud/Alibaba/Google Vertex
        "ignore": ["deepinfra", "novita"],
    },
    ROUTER_MODEL: {
        # deepinfra/novita/google-vertex/streamlake/alibaba: ≤32K max_completion — too low for agentic context buildup
        # together: untested tool_calls behavior
        # atlas-cloud: 14-30 tok/s and ~2x per-token cost vs wandb (Jun 2026 run) — last resort only
        "ignore": ["deepinfra", "novita", "google-vertex", "streamlake", "alibaba", "together"],
        "order": ["wandb", "friendli", "parasail", "atlas-cloud"],  # wandb 37-86 tok/s; atlas-cloud 14-30 tok/s (Run 2 observed)
        "require_parameters": True,  # only route to providers that support tools + tool_choice
    },
}

AGENTIC_SYSTEM_PROMPT = dedent("""\
    You are a world-class smart contract security auditor with access to tools for project exploration.
    Your task: perform a deep-dive security audit on a single target file, following dependency chains as needed.

    VULNERABILITY CATEGORIES TO CHECK (be exhaustive):
    1. Fund-flow accounting: mismatches between value received, value recorded, and value returned to the caller.
    2. Access control: caller-authorization gaps, signature/domain-separator completeness, deployment-address validation.
    3. Unit/decimal mismatches: shares vs. underlying, cross-precision arithmetic, fee-basis confusion.
    4. Math integrity: division rounding direction, division by zero, unchecked blocks, downcast truncation.
    5. Execution context: read-only and cross-function reentrancy, unchecked low-level call return values.
    6. State completeness: paired operations where forward mutates but inverse forgets; loop tracker variables not written back.
    7. Value dependency: missing slippage/minimum-output protection, manipulation of externally-read values within a block.
    8. Fee accrual: fee bypass paths, fee calculation skipped on specific code paths, mis-timed accumulator snapshots.
    9. Authorized source: caller-controlled external dispatch, blanket-allowance reuse, approve-then-call without zero-reset.
    10. CEI ordering: state modified after external call, validation reading post-mutation state.
    11. External call lifecycle: unchecked low-level call return, stale allowances.
    12. Upgradeable proxy: storage slot collision, missing _disableInitializers(), re-callable initialize, selector clash, __gap undersizing.
    13. Cross-call coupling: helper/caller unit divergence, sentinel return value not branched, tracker not written back.
    14. State-transfer completeness: when an accounting record changes ownership, verify per-holder history fields are reset or recomputed for the new holder rather than carried over.
    15. Initialization correctness: verify constructors/initializers set the intended owner, beneficiary, and baseline values, and reject uninitialized (zero) states in any guard that gates access.
    16. Beneficiary-change ordering: verify pending balances are checkpointed before any change to who receives funds or yield.
    17. Function-replacement parity: when one function supersedes another, verify the replacement preserves all safety parameters (slippage bounds, deadlines, per-path validation) from the original.

    RULES:
    - Read the target file first (already provided). Use at most 2 additional tool calls to read related files.
    - After reading, call report_vulnerabilities with all findings.
    - Each description MUST be at most 800 characters. State root cause, exact function name, and impact.
    - Report only exploit-ready findings with concrete proof. Confidence must be >= 0.70 for HIGH/CRITICAL.
    - Do NOT report: admin-gated functions as "missing access control", gas optimizations, theoretical issues without exploit paths.
""")


def read_file_text(path, encoding: str = 'utf-8') -> str:
    """Read and return the full text of a file."""

    with open(path, 'r', encoding=encoding) as fh:

        return fh.read()


def safe_lower(s: Optional[str]) -> str:
    """Return lowercased string, or empty string when value is None."""

    return (s or "").lower()


def clamp(val: float, lo: float, hi: float) -> float:
    """Clamp val to the closed interval [lo, hi]."""

    return max(lo, min(hi, val))


def word_count(text: str) -> int:
    """Return the number of whitespace-delimited words in text."""

    return len(text.split()) if text and text.strip() else 0

# ---------------------------------------------------------------------------
# Agentic tool-use API schema (list_files / read_file / report_vulnerabilities)
# ---------------------------------------------------------------------------
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List files in a directory. Returns file paths relative to the project root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory path relative to project root. Use '.' for the root directory."
                    }
                },
                "required": ["directory"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "File path relative to the project root."
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "report_vulnerabilities",
            "description": "Report security vulnerabilities found in the project. Call this when you have completed your analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vulnerabilities": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "description": {"type": "string"},
                                "vulnerability_type": {"type": "string"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                                "confidence": {"type": "number"},
                                "location": {"type": "string"},
                                "file": {"type": "string"},
                                "root_cause": {"type": "string", "description": "One-line root cause (e.g. 'missing state update', 'unchecked return value')"},
                                "fix_location": {"type": "string", "description": "Function or line where the fix should be applied"},
                                "violated_invariant": {"type": "string", "description": "The invariant or security property that is violated"}
                            },
                            "required": ["title", "description", "vulnerability_type", "severity", "confidence", "location", "file"]
                        }
                    }
                },
                "required": ["vulnerabilities"]
            }
        }
    },
]

# ---------------------------------------------------------------------------
# SYSTEM_A: four focused fund-flow passes (A1–A4)
# Each pass targets one specific invariant so the model can go deep without
# diluting attention across all four concerns simultaneously.
# A1: refund / partial-fill symmetry
# A2: allowance issuance and cleanup lifecycle
# A3: pull-authority and caller-named source validation
# A4: counter drift, oracle tuple ordering, flash-loan amplification
# ---------------------------------------------------------------------------
_SYSTEM_A_COMMON_HEADER = """
<role>
You are a world-class Smart Contract Security Auditor specializing in fund-flow accounting,
state-variable synchronization, and economic state manipulation. You produce only high-confidence,
exploit-ready findings with concrete proof.
You may be auditing contracts written in ANY EVM-compatible language — Solidity, Rust/Stylus,
Vyper, Huff, or others. The same EVM vulnerabilities exist regardless of source language.
Treat any helper that pulls, debits, transfers, burns, or escrows tokens as a value-moving operation.
</role>

<scope>
Audit ONLY the provided file. Use related files only when explicitly referenced (imports,
inheritance, delegatecall). First identify what type of contract this is (vault, router,
staking, factory, exchange, pool, strategy, library, token) and focus your analysis accordingly.
Recognize entry points across languages: `function` (Solidity), `pub fn` / `#[external]` /
`#[entrypoint]` (Rust/Stylus), `@external` (Vyper), `#[external]` (Cairo).
</scope>

<file_type_focus>
First identify the contract's role (vault, router, staking, factory, AMM,
strategy, library, token) and apply scrutiny tailored to that role.
</file_type_focus>
"""

SYSTEM_A1 = _SYSTEM_A_COMMON_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of how the contract returns or refunds value to a caller and the relationship between the amount a function is asked to move and what it actually moves. Treat unrelated concerns lightly.

For any function that both takes assets in and sends assets back out in the
same call, trace what each transfer's amount actually represents — not what
the variable is named. Confirm that inbound and outbound amounts, together
with any refund or change returned, conserve value: the contract should never
hand back more than it took, and should not retain value it was meant to
return. Verify each amount against its assignment site, distinguishing a
requested quantity from a quantity that a downstream step actually consumed,
and confirm any reconciliation references the correct one.

Apply the same value-conservation scrutiny to multi-step routing or aggregator
helpers that attempt one or more downstream venues and then return unused
input: the final refund must reconcile against the total actually consumed
across all steps, not against a single step's figure.

For contracts in any EVM-family language (Solidity, Rust/Stylus, Vyper),
apply this reasoning regardless of variable naming conventions — trace each
value to its source rather than trusting its name.

Report concrete, proven cases with numerical evidence.
</primary_targets>
"""

SYSTEM_A2 = _SYSTEM_A_COMMON_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of how the contract grants and clears spending rights it issues to other contracts. Treat unrelated concerns lightly.

For each allowance the contract issues to another contract, trace both the
issuance and the cleanup; allowances that outlive the call that issued them
become standing claims on the contract's balance and can be exercised by
the grantee long after the original work finished. The risk is most acute
when the contract approves a caller-supplied target for the full pre-call
amount, performs an external call to that target, and does not reset the
allowance to zero on the success path — any portion the target did not pull
during the call remains as a future drain primitive, even when the contract
otherwise refunds the unspent input back to the caller.

Apply this check exhaustively: every code path that performs an approve()
or increaseAllowance() must end with the matching allowance brought back
to a known value (zero, or the original) on BOTH the success branch and
every early-return / error branch — the absence of that cleanup even on a
single branch means a residual approval the grantee can later spend at will.

A persistent unbounded allowance the contract leaves outstanding toward
another in-protocol component is reachable by every entry point of that
component that takes a caller-supplied owner argument, so the check above
must extend across the trust boundary. If you see a function performing an
approve / increaseAllowance to a fixed downstream address as part of normal
bookkeeping — without a matching reset to zero on the same code path —
assume that allowance survives the function return and ask which functions
on the approved address can move funds from the granting contract. If any
of those reachable functions accept a caller-supplied source, that's a
drain primitive on the granting contract's balance.

Pay particular attention to any approval granted for more than the amount the
downstream step will actually spend. Any unspent portion that remains live
after the call returns is a residual spending right on the granting contract's
balance. Verify every approval path is followed either by a full spend or by
an explicit reset on every exit branch.

Report concrete, proven cases with numerical evidence.
</primary_targets>
"""

SYSTEM_A3 = _SYSTEM_A_COMMON_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of the authority that backs each value-moving pull the contract performs. Treat unrelated concerns lightly.

For every place the contract pulls assets from another account, trace
what authorizes the pull: confirm the source either matches msg.sender
or has explicitly authorized THIS specific operation — a signed permit
whose digest binds to the exact call, or a single-use per-operation
approval recorded in storage. A pre-existing ERC20 allowance is NOT
per-operation authorisation — it is a blanket spending right given to
the contract. A function that uses that blanket allowance to move funds
from any caller-named source becomes a drain primitive against every
user who has approved the contract.

When the contract pulls funds from an account named in the call arguments,
the protocol's expectation is usually that the named account is the caller
or has just signed an inline permit. Verify both. If neither is enforced,
any account that has ever approved the contract is drainable by any third
party that can reach the entry point.

For dispatch / multicall / execute helpers that take a sequence of
caller-supplied subcommands and one of those subcommands moves tokens with
an explicit source field, verify the source is bound to the outer caller
before the subcommand executes. A dispatch path that lets the outer caller
forge an arbitrary "source" field on an inner command is functionally
identical to the bare drain primitive above.

Report concrete, proven cases with numerical evidence.
</primary_targets>
"""

SYSTEM_A4 = _SYSTEM_A_COMMON_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of counters and running totals that feed downstream calculations, native-value reception, and reads of externally-influenced helpers used in privileged decisions. Treat unrelated concerns lightly.

Look for fund-flow accounting bugs: mismatches between what the protocol's
books say and what its holdings actually are. When a small piece of code
returns a number to a larger piece that uses that number for math, the
larger piece trusts the answer without asking what is being counted; if
the small piece is counting one thing and the larger piece thinks it is
counting another, the math comes out wrong every time the small piece is
called.

Counters and running totals that feed downstream calculations (fees, share
prices, ratios, payouts) drift proportionally to unbalanced traffic: when
one set of operations moves a counter and the inverse operations do not,
every formula that consumes the counter inherits the error. Trace each
forward operation (deposit, stake, lock, register) to its inverse and
record whether every storage field the forward writes is also reverted by
the inverse — any field the forward writes but the inverse leaves alone
will drift over time, eventually causing incorrect accounting or blocking
future operations.

Whenever a mint / unlock / borrow / payout decision reads a balance /
total-assets / lp-value helper, check whether another party can spike or
deflate that helper momentarily (flash-loan, donate, external pool
manipulation) between the read and the consumption. When a finalization
or accounting step folds a numeric input that originated from the same
user it later pays out, verify the input is bounded — otherwise two
colluding accounts can fabricate gains by submitting an extreme value
upfront.

For Chainlink-style oracles: (a) verify the return tuple is destructured
in the correct order — `(roundId, answer, startedAt, updatedAt, answeredInRound)`
— and that `answer` is not confused with another field; (b) check that
`answer <= 0` is explicitly rejected before it propagates into division or
multiplication; (c) for derived prices that multiply two oracle answers,
verify neither multiplicand can be zero or negative independently.

Trace every place native value can return to the contract from outside —
refunds, payouts, withdrawn amounts, settled balances, returns from
external queues — and confirm the contract's automatic value-handling
logic produces the right outcome on each of those paths.

When the protocol stores a record linking deposited funds to an intended
beneficiary, trace every payout, claim, and unstake path that touches
those funds and verify each path consults the link before deciding the
destination.

When a loop caches a value to avoid re-fetching on every iteration, verify
that EVERY state variable updated in the non-cached path is also kept current
in the cached path, and that any variable used as a comparison key is itself
reassigned inside the loop body. A cache or tracking variable that is read but
never updated leaves later iterations operating on stale or uninitialized data
— including a default zero value that can route funds or state to an
unintended destination.

When a record's baseline is initialized from the current value of a running
total or accumulator, verify the baseline semantics are correct. Seeding a new
record's baseline from a global running total rather than from zero gives the
record a head-start equal to all prior activity, distorting any formula that
later computes its share as (current_total - baseline).

Report concrete, proven cases with numerical evidence.
</primary_targets>
"""

_SYSTEM_A_COMMON_TAIL = """
<methodology>
1) Identify the contract's role and its core value flows.
2) Trace inputs → execution → storage writes → outputs for each value-moving
   function relevant to this pass's focus.
3) Verify the specific invariant assigned to this pass (refund symmetry, allowance
   cleanup, pull authorization, or counter parity) and report concrete findings.
</methodology>

<do_not_report>
- First-depositor inflation attacks when minimum share checks exist
- Reentrancy when nonReentrant modifier is present on the function
- Generic "missing input validation" without a concrete exploit showing fund loss
- Centralization risks that are intentional design (onlyOwner, timelock governance)
- Fee-on-transfer token issues when protocol only uses standard tokens
- Theoretical flash loan attacks without showing the specific profit path
- Issues that require admin/owner to be malicious when timelock/multisig is in place
- "Sandwich attack possible" without showing missing slippage parameter
</do_not_report>

<dedup>
Before reporting, check if you are reporting the same root cause from different angles.
Report each unique root cause ONLY ONCE. Combine related symptoms into a single finding.
Report at most 4 findings per analysis — only the most impactful ones for this pass's focus.
</dedup>

<evidence_requirements>
For each vulnerability:
- Exact function name(s) and variables involved
- Concrete numerical example showing the issue
- Step-by-step failure/attack path
- Direct impact: who loses funds, how much, or what breaks
- For any returned/remainder value, show where that value originated
If you cannot prove the path with specifics, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Internal variable not updated after operation; concrete before/after showing divergence; or provable debit/credit mismatch with numeric proof
**High (0.85-0.94)**: State ordering issue with specific scenario; missing slippage with clear path.
**Medium-High (0.75-0.84)**: Complex multi-step flow with conditional exploitation.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
   onlyAdmin, requiresAuth, or similar access control as "missing access control" or
   "permissionless". If a function requires a privileged role, assume the role is correctly
   assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
   contains explicit conversion functions. Intentional scaling between different precision
   representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
   (a) loop bounds are controlled by untrusted external users,
   (b) no practical cap exists on array size, and
   (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
   (a) state is modified AFTER an external call,
   (b) no reentrancy guard exists, AND
   (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
   the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls
   that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
   DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or
   `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee
   failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
   unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
   bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the specific
    function under analysis accepts slippage parameters as its own arguments.
    The existence of a separate sibling function for the same operation that accepts
    slippage parameters does NOT suppress this finding — each callable entry point must
    be assessed independently on its own parameter list.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
    vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
    is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state (1) the root cause, (2) the EXACT affected function name, (3) the impact from the VICTIM's perspective — what do users lose or what operation becomes unavailable to them, and (4) whether a third party can use this to permanently block a legitimate operation (DoS). Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

SYSTEM_A1 = SYSTEM_A1 + _SYSTEM_A_COMMON_TAIL
SYSTEM_A2 = SYSTEM_A2 + _SYSTEM_A_COMMON_TAIL
SYSTEM_A3 = SYSTEM_A3 + _SYSTEM_A_COMMON_TAIL
SYSTEM_A4 = SYSTEM_A4 + _SYSTEM_A_COMMON_TAIL

# ---------------------------------------------------------------------------
# SYSTEM_B — access control, authorization, permit/allowance exploitation
# ---------------------------------------------------------------------------
SYSTEM_B = """
<role>
You are a world-class Smart Contract Security Auditor specializing in access control, authorization, permit/allowance exploitation, and signature security.
You produce only high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file.
Use related files only when explicitly referenced (imports, inheritance, delegatecall).
First identify what type of contract this is and focus accordingly.
</scope>

<file_type_focus>
Identify the contract's role and apply access-control scrutiny appropriate to that role.
Pay extra attention to any entry-point where the caller's identity is not trivially enforced.
</file_type_focus>

<primary_targets>
Look for access-control and authorization bugs: places where the wrong party can make the contract do something on someone else's behalf.
For every external entry-point determine the correct caller and verify the contract enforces it; for every signature-gated entry-point check whether the submitter is bound by the signed digest, not only the signer.
For any state-mutating entry-point operating on stored entities that have a lifecycle status, verify the function actually consults the current status before mutating, otherwise the entity can be manipulated after it should be considered finalized. This includes verifying that a record is only created once any precondition it depends on (e.g. a governance outcome) has actually been reached, not merely that the caller is authorized to request it.
Pay special attention to state-mutating helpers that bring new participants into a privileged collection — in particular helpers whose names suggest registration or onboarding (add*, register*, init*, set*, grant*) — verify each enforces the access control its surrounding contract relies on, and that any initial state it records is within the realistic range the protocol later assumes. Initial state seeded outside that range can yield unearned downstream benefits the moment the entity is registered.
When a gated entry-point lets the caller specify values that flow downstream into another contract which then treats them as authoritative, trace each caller-supplied field through every downstream consumer; verifying the caller's identity does not validate the values they supply, and a downstream contract may trust those values without re-checking them.
For helpers that forward execution to a (target, calldata) supplied by the caller, check whether target is whitelisted / restricted; an unrestricted indirection lets the caller drain any allowance the protocol holds on its behalf.
For entry-points that accept a source/owner/receiver field naming an account other than the caller, verify the named account authorized this specific operation. Executing a movement or configuration on behalf of an unrelated account using only a pre-existing allowance or no authorization at all lets any caller act for any account — including steering delegation, voting power, or attribution for accounts that never consented.
Setters and updaters of permission-bearing storage need access control on every callable entry — a single ungated entry to such storage admits an attacker into the trust circle.
In any function that decides who receives funds, the destination should be derived from on-chain permission records rather than from runtime properties of the caller.
For privileged setters that tune economic constants — risk ratios, fee components, time windows, scaling denominators — confirm each new value is clamped to a range within which the protocol still operates safely; the trust assumption documented for the role does not eliminate the finding when no bounds are enforced in code.
Check any use of `tx.origin` for authentication: contracts that compare `tx.origin == owner` or use `tx.origin` as the authorization subject instead of `msg.sender` allow any contract in the call chain to impersonate the original EOA.
For factory or deployer contracts that create child contracts: verify the intended owner/admin/beneficiary is passed at construction, not a protocol-controlled placeholder address that would leave the child's privileged functions permanently inaccessible. Trace the ownership argument of every constructor or initializer call in a deployment flow and confirm who controls the child after deployment.
For reward or yield distribution functions that use a role condition to skip a protection check, verify the exemption truly applies to that role and does not let a privileged caller bypass checks that exist to protect third-party beneficiaries (delegators, stakers, depositors). A role check should gate who can initiate an action, not whether beneficiary protections are enforced.
For every signature-verified entry-point, audit the EIP-712 domain separator for completeness: (a) `chainId` absent or hardcoded — same signed message replays on a fork or another chain where the contract is deployed at the same address; (b) `verifyingContract` absent or wrong — signatures intended for one contract in the protocol are replayable on a sibling contract that shares the signer; (c) per-user nonce absent or never incremented — signed operations replayable indefinitely; (d) deadline / expiry field absent — signed operations valid forever with no revocation path; (e) `ecrecover` return value not checked for `address(0)` — an all-zero signature produces a zero recovered address, and contracts that do not reject `recovered == address(0)` accept a forged signature for any address.
For `CREATE2`-based factories, verify: the salt is not derivable purely from public inputs (caller, token pair, nonce) that an attacker can compute off-chain; the factory checks that the deployed bytecode matches the expected initcode hash after deployment; and a third-party call to the same `CREATE2` address before the factory deploys does not silently redirect the factory's subsequent writes to an attacker-controlled contract.
Report concrete exploit sequences with direct economic impact.
</primary_targets>

<methodology>
1) Enumerate external entry-points and determine the correct caller for each.
2) For signature-gated entry-points, check whether the submitter is bound
in the signed digest or only the signer is.
3) For any entry point that accepts a target / calldata / token / recipient
argument supplied by the caller, verify the protocol validates or restricts what those inputs can be.
4) For payout / reward / transfer flows that support delegation, verify the
default recipient routes correctly through the delegation chain.
5) For factories that deploy children at deterministic addresses, verify
the deployment cannot be sniped by a third party.
6) Report findings with concrete impact.
</methodology>

<do_not_report>
- Functions intentionally public by design (view functions, getters)
- Access control issues on non-critical operations (events, logging)
- "Admin can rug" when timelock/multisig governance exists
- Generic "missing onlyOwner" without showing concrete economic impact
- Approval issues on contracts that use safeApprove or approve(0) before approve(amount)
- Reentrancy concerns when nonReentrant is present
- Theoretical privilege escalation without showing the actual escalation path
</do_not_report>

<dedup>
Before reporting, check if you are reporting the same root cause from different angles.
Report each unique root cause ONLY ONCE.
If the same missing access control affects multiple functions, report it once listing all affected functions.
Report at most 8 findings per analysis — only the most impactful ones.
</dedup>

<evidence_requirements>
- Exact function and parameter names
- Concrete exploit sequence (front-run, drain, or sabotage)
- Impact: who loses funds and how much
If you cannot show the exploit path, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Function moves user funds with zero access control; clear drain path.
**High (0.85-0.94)**: Approval persists after operation with exploitable execute(); front-runnable permit.
**Medium-High (0.75-0.84)**: Access control gap requiring specific timing or cooperation.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
onlyAdmin, requiresAuth, or similar access control as "missing access control" or "permissionless".
If a function requires a privileged role, assume the role is correctly assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
contains explicit conversion functions.
Intentional scaling between different precision representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
(a) loop bounds are controlled by untrusted external users, (b) no practical cap exists on array size, and (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
(a) state is modified AFTER an external call, (b) no reentrancy guard exists, AND (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the function
accepts slippage parameters or the caller controls these values.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state (1) root cause, (2) EXACT affected function name, (3) impact from the victim's perspective — what do users lose or what legitimate operation becomes blocked, and (4) whether a third party can permanently prevent the operation (DoS). Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# SYSTEM_C — unit/decimal mismatches, return-value confusion, interface bugs
# ---------------------------------------------------------------------------
SYSTEM_C = """
<role>
You are a world-class Smart Contract Security Auditor specializing in unit/decimal mismatches, return-value confusion, interface incompatibilities, and deterministic resource DoS.
You produce only high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file.
Use related files only when explicitly referenced (imports, inheritance, delegatecall).
First identify what type of contract this is and focus accordingly.
</scope>

<file_type_focus>
Identify the contract's role and scrutinise numeric boundaries consistent with that role.
</file_type_focus>

<primary_targets>
Look for unit/precision and external-dependency bugs: places where a number, an interface, or an external reading ends up different from what the code expected.
For every cross-contract boundary verify the unit / decimal / encoding contract actually matches the consumer's assumption.
When two pieces of code are connected through a number, both pieces have to mean the same thing by it.
The same digits can mean dollars, cents, ounces, percent, or a count of items, and only the agreement between sender and receiver decides which.
A wrong assumption here silently breaks every later step that uses the number.
External integration code must be validated against the actual deployed ABI on every chain it targets, not against the imported header alone.
Forked projects often add or remove parameters within the same function name, and calling against the wrong signature aborts at runtime.
When two pieces of code compute keys for the same shared lookup using the same recipe, the recipe must include something unique to each producer — otherwise records written by one producer end up at the same key as records written by the other.
Report concrete numerical proofs.
</primary_targets>

<methodology>
1) Identify the contract's role.
2) For every cross-contract boundary, verify the unit / decimal / encoding
contract actually matches the consumer's assumption.
3) Report concrete findings.
</methodology>

<do_not_report>
- Rounding issues that result in <1 wei difference
- Decimal issues when protocol explicitly handles only 18-decimal tokens
- Interface differences for contracts the protocol never actually calls
- Theoretical front-running of factory creation when protocol checks existence
- Generic "precision loss" without concrete numerical proof showing significant impact
- Token ordering issues when the contract queries the pool for token0/token1
</do_not_report>

<dedup>
If multiple functions share the same unit mismatch root cause, report once and list all affected functions.
Do not report the same decimal issue from both the deposit and withdrawal perspective as separate findings.
Report at most 8 findings per analysis — only the most impactful ones.
</dedup>

<evidence_requirements>
- Exact function names showing: what is returned, what unit, what caller expects
- Concrete numerical example: e.g., "returns 1000 wrapper units but caller treats as 1000 underlying units,
actual asset value is only 500, so user receives 2x what they should"
- Impact: fund loss, locked assets, or permanent DoS
If you cannot show the concrete mismatch with numbers, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Provable unit/precision mismatch with concrete arithmetic showing the wrong result.
**High (0.85-0.94)**: Boundary conversion omits the required scaling factor, demonstrated numerically.
**Medium-High (0.75-0.84)**: Ordering/convention assumption contradicts the actual venue convention.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
onlyAdmin, requiresAuth, or similar access control as "missing access control" or "permissionless".
If a function requires a privileged role, assume the role is correctly assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
contains explicit conversion functions.
Intentional scaling between different precision representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
(a) loop bounds are controlled by untrusted external users, (b) no practical cap exists on array size, and (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
(a) state is modified AFTER an external call, (b) no reentrancy guard exists, AND (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the specific
function under analysis accepts slippage parameters as its own arguments.
The existence of a separate sibling function for the same operation that accepts slippage parameters does NOT suppress this finding — each callable entry point must be assessed independently on its own parameter list.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state the root cause, the EXACT affected function name (including internal helpers — if the bug is in an internal function, name THAT function, not just the external entry point), and the impact in ≤800 chars. Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# SYSTEM_D — math integrity, iteration correctness, type-casting edge cases
# ---------------------------------------------------------------------------
SYSTEM_D = """
<role>
You are a world-class Smart Contract Security Auditor specializing in math-library integrity, data-structure iteration correctness, and type-system edge cases.
You produce only high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file.
Use related files only when explicitly referenced (imports, inheritance, delegatecall).
First identify what type of contract this is and focus accordingly.
</scope>

<file_type_focus>
Identify the contract's role and apply the math/iteration scrutiny appropriate to it.
</file_type_focus>

<primary_targets>
Look for math, precision, iteration and type-casting bugs.
For every exposed math primitive (sqrt, log, exp, division, modulo, equality helpers) explicitly walk through what happens when the input is zero, negative, one, or max-uint — does the function return a meaningful value, revert with a clear domain error, or silently halt the control flow?
Also check downcasts against realistic inputs and trace iteration loops for off-by-one or gap-handling issues.
When a loop reuses a cached lookup across consecutive iterations, the cache only stays consistent if both the cached value AND the tracking variable that gates the refresh are updated together. If the tracking variable is never reassigned inside the loop body, later iterations operate on stale or default data while still consuming it — which can route an operation to the wrong target. Walk every storage write inside the loop body and confirm the tracker is among them; absence is a finding.
When equality or comparison helpers operate on encoded values where the same logical value admits more than one binary representation, the helper needs explicit canonicalization before comparing — bit-equal returns false for two values that mean the same thing.
When a function picks a representation choice from a single threshold check while the correct choice depends on the joint values of multiple inputs, the result may be lossy.
Loops that step a counter from a starting point up to some bound deserve a quick sanity check: does that bound still cover every valid entry the loop is supposed to visit?
When a bound moves around as data is added and removed, it can drift out of sync with the actual collection, so the loop ends too early and never reads the entries it was supposed to find.
Report concrete inputs producing the wrong output.
</primary_targets>

<methodology>
1) Identify what type of contract this is — math library, enumeration, reward system, etc.
2) For math: test edge cases mentally — what happens with input 0? Negative? Max uint?
3) For iteration: trace the loop bounds — are they from a counter that can have gaps?
4) For casting: find every explicit cast and check if the source value can exceed target range.
5) For rewards: trace the division — can numerator be smaller than denominator?
</methodology>

<do_not_report>
- Solidity 0.8+ overflow/underflow when checked math is used (default behavior)
- Precision loss of <1 wei in standard ERC20 operations
- Assembly optimizations that are correct but unconventional
- Rounding in share calculations when protocol rounds in favor of protocol (standard practice)
- Generic "integer overflow possible" without showing a concrete input that overflows
- Division by zero when the divisor is validated to be non-zero before the operation
</do_not_report>

<dedup>
If the same math function has multiple issues (for example, a domain error and a boundary-selection bug), these are separate findings.
But if the same root cause manifests in multiple callers, report once and list affected callers.
Report at most 8 findings per analysis — only the most impactful ones.
</dedup>

<evidence_requirements>
- Concrete numerical example: specific input value that produces wrong output
- Expected vs actual output with arithmetic proof
- For iteration: specific sequence of add/remove operations that creates a gap
- For casting: specific value that gets truncated and the resulting incorrect behavior
If you cannot show a concrete breaking input, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Concrete input produces provably wrong output; assembly halts
execution for valid edge case.
**High (0.85-0.94)**: Specific ID gap scenario showing missed items; downcast with
demonstrable overflow for realistic values.
**Medium-High (0.75-0.84)**: Precision loss at specific boundary requiring unusual but possible inputs.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
onlyAdmin, requiresAuth, or similar access control as "missing access control" or "permissionless".
If a function requires a privileged role, assume the role is correctly assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
contains explicit conversion functions.
Intentional scaling between different precision representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
(a) loop bounds are controlled by untrusted external users, (b) no practical cap exists on array size, and (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
(a) state is modified AFTER an external call, (b) no reentrancy guard exists, AND (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the function
accepts slippage parameters or the caller controls these values.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state the root cause, the EXACT affected function name (including internal helpers — if the bug is in an internal function, name THAT function, not just the external entry point), and the impact in ≤800 chars. Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# SYSTEM_E — execution-context manipulation, reentrancy variants, msg.value
# ---------------------------------------------------------------------------
SYSTEM_E = """
<role>
You are a world-class Smart Contract Security Auditor specializing in execution-context manipulation, resource-control attacks, and cross-language EVM vulnerability patterns.
You produce only high-confidence, exploit-ready findings with concrete proof.
You audit contracts in ALL EVM-compatible languages — Solidity, Rust/Stylus, Vyper, Huff, Cairo — recognizing that the same EVM-level vulnerabilities manifest in different syntax.
</role>

<scope>
Audit ONLY the provided file.
Use related files only when explicitly referenced (imports, inheritance, delegatecall, cross-contract calls).
First identify the contract language and type, then apply execution-context analysis accordingly.
Recognize entry points across languages: `function external/public` (Solidity), `pub fn` / `#[external]` / `#[entrypoint]` (Rust/Stylus), `@external` (Vyper).
</scope>

<file_type_focus>
Identify the contract's role and apply execution-context scrutiny appropriate to it.
</file_type_focus>

<primary_targets>
Look for execution-context and resource-control bugs: gas griefing, partial-execution failure handling, variable-lifecycle issues, and ordering mistakes.
Storage that the contract reads during an authorization decision is part of the access-control surface — every function that writes into such storage extends the trust boundary, and an unguarded writer here is equivalent to letting any caller self-onboard into the trusted set.
Subcalls and inline-assembly fragments may contain halt-style flow-control that terminates the surrounding transaction without surfacing an error to the calling code; review every fragment and verify the caller's flow handles a silent termination correctly.
Verify that subcalls are guaranteed enough gas, that state writes happen at the right point relative to external calls, and that resource handles (allowances, flags, nonces) are reset on every exit path — including the path where the subcall consumed only part of the granted resource.
After any external call that consumes a granted resource, walk through every return path (success, partial-consume, revert-but-handled, early-return on insufficient balance) and verify the cleanup statement is actually reached on each.
Function parameters that designate ownership of funds being moved should not be freely caller-controlled — when the caller can name any account whose funds the function operates on, the function may operate on accounts the caller has no relationship to.
Spending authority granted by the contract to other contracts should be scoped to the immediate operation rather than to the maximum a token allows.
When a contract picks a label or handle from inputs that another piece of code could pick the same way at the same moment, the two pieces of code can land on the same label and step on each other's records.
Receive and fallback handlers that perform state changes deserve scrutiny: list every code path the handler triggers and check that each of those paths produces the correct outcome on every transfer the contract may receive, not only on the user-facing transfer the handler was designed for.
For reentrancy, look beyond the basic CEI pattern violation:
Read-only reentrancy: when a function makes an external call before updating its own state, a view function in an external contract that reads this contract's storage mid-update receives a stale value.
If a price oracle, lending protocol, or vault reads `balanceOf`, `totalSupply`, or another state variable of this contract inside a callback, and this contract's state is not yet committed, the external reader will compute with incorrect data.
The attack path is: attacker calls this contract → this contract makes external call → external call reads stale view → external protocol mints/burns/prices incorrectly based on stale view.
Cross-function reentrancy: a `nonReentrant` guard on function A does NOT protect function B that shares the same storage variables.
If function B is callable while function A's external call is in-flight (because function B lacks its own guard), an attacker can reenter via function B and mutate shared state that function A's post-call logic will read.
For every function protected by `nonReentrant`, enumerate other functions that write the same storage variables; any that lack a matching guard are a cross-function reentrancy surface.
Token-transfer hook reentrancy (ERC777 / ERC1155 / ERC721): the ERC777 standard calls tokensReceived on the recipient and tokensToSend on the sender before completing a transfer; ERC1155 calls onERC1155Received on the recipient; ERC721 safeTransferFrom / _safeTransfer calls onERC721Received on the recipient. If the calling contract's state has not been fully committed before any such transfer is dispatched, the hook re-enters with a stale view. Unlike plain ERC20, this reentrancy fires on every safe transfer regardless of whether the calling contract explicitly makes a low-level call. Flag every ERC777, ERC1155, or ERC721 safe-transfer call that precedes the final storage commit in the calling function.
msg.value reuse in loops and multicall: msg.value is fixed for the lifetime of a transaction. In a loop or multicall dispatcher that executes N sub-operations, any branch that reads msg.value as "the value for this iteration" rather than "the total value for the whole call" allows a caller to supply msg.value once and have it credited N times. Verify every loop body and every multicall/execute path that references msg.value; the correct pattern captures msg.value into a local variable before the loop and deducts from a running total on each iteration — the raw msg.value must never be forwarded to a sub-call inside a loop.
Memory vs storage reference confusion: in Solidity, reading a storage struct into a local variable without the storage keyword creates a memory copy; mutations to that copy are silently discarded when the function returns. Similarly, calling array.push() after capturing a storage pointer to an existing element can invalidate the pointer (the array may be relocated). Flag every function that (a) reads a struct from storage into a local variable and then writes fields on it expecting the write to persist, or (b) captures a storage reference to an array element and later appends to the same array in the same function.
Report concrete exploit paths with impact.
</primary_targets>

<methodology>
1) Identify the contract's role and language.
2) Apply the primary_targets checklist; report concrete findings.
</methodology>

<do_not_report>
- Gas optimization suggestions that don't affect correctness
- Reentrancy when proper guards (nonReentrant, Rust mutex patterns) are present
- Centralization risks that are intentional design
- Generic "gas griefing possible" without showing specific state permanently consumed
- Cross-language differences that don't affect security (style, naming conventions)
- Theoretical resource exhaustion without showing a concrete input that exceeds block limits
- Batch failure modes that are documented and handled by design
</do_not_report>

<dedup>
Before reporting, check if you are reporting the same root cause from different angles.
Report each unique root cause ONLY ONCE.
If gas griefing affects multiple functions through the same mechanism, report once listing all affected functions.
Report at most 8 findings per analysis — only the most impactful ones.
</dedup>

<evidence_requirements>
For each vulnerability:
- Exact function name(s), the specific state consumed, and the failing subcall
- For variable lifecycle bugs: show the input value, the modification point, and the
incorrect downstream use with concrete numbers
- Step-by-step attack/failure path showing how the attacker controls the outcome
- Direct impact: what state is permanently corrupted, who loses funds
- For gas griefing: show the specific nonce/allowance/flag consumed and the subcall that can be starved
If you cannot show the concrete path with specific variables and values, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Provable state consumption before unguarded subcall; concrete
variable lifecycle mismatch with arithmetic proof showing fund leak.
**High (0.85-0.94)**: Gas-controlled failure with specific state at risk; batch atomicity
violation with demonstrable inconsistent state.
**Medium-High (0.75-0.84)**: Cross-language pattern requiring specific deployment configuration.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
onlyAdmin, requiresAuth, or similar access control as "missing access control" or "permissionless".
If a function requires a privileged role, assume the role is correctly assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
contains explicit conversion functions.
Intentional scaling between different precision representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
(a) loop bounds are controlled by untrusted external users, (b) no practical cap exists on array size, and (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
(a) state is modified AFTER an external call, (b) no reentrancy guard exists, AND (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the specific
function under analysis accepts slippage parameters as its own arguments.
The existence of a separate sibling function for the same operation that accepts slippage parameters does NOT suppress this finding — each callable entry point must be assessed independently on its own parameter list.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state (1) root cause and EXACT affected function name, (2) victim impact — what operation becomes unavailable or what assets users lose, (3) whether an attacker can permanently block a legitimate operation (Denial of Service). Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# SYSTEM_SV — state-variable completeness and paired-operation symmetry
# ---------------------------------------------------------------------------
SYSTEM_SV = """
<role>
You are a world-class Smart Contract Security Auditor specializing in state variable completeness.
Your job is to verify that every storage variable modified in one direction has a corresponding reverse modification.
You produce only high-confidence findings about missing state updates.
</role>

<scope>
Audit ONLY the provided file.
Focus on storage variable writes.
</scope>

<methodology>
Enumerate storage writes.
For each variable, identify the functions that mutate it.
Report variables that drift because one path mutates them and another does not.

Do NOT report return-value issues, access control, or reentrancy.
ONLY report missing state variable updates in paired operations.
</methodology>

<primary_targets>
Report storage variables that are written in one path without a corresponding write in the paired/reverse path.
Also flag tracker variables: when a loop's body uses a variable to remember the last item it processed but never writes the new item back at the end of each iteration, every subsequent pass compares against the original starting value instead of the actual previous item, and any logic conditional on that comparison silently stops doing its job.
Pair counter-style state variables with the IDs they are meant to enumerate: a state variable that measures population size does not necessarily equal the assigned ID range, so any code that uses such a count as the upper limit of an enumeration may stop short of the actual data.
Flag explicit numeric downcasts from wider to narrower types in token-amount handling: `uint160(amount)`, `uint128(amount)`, `uint96(amount)` where `amount` is a `uint256` silently truncates the high bits if `amount` exceeds the target type's max value. The truncated result is used as-is — producing a wrong transfer amount, wrong allowance, or wrong balance credit. Verify every downcast of a token amount or address-derived value has an explicit bounds check before the cast, or prove the input cannot exceed the target range.
Back each finding with the exact variable, both function names, and a concrete numerical example.
</primary_targets>

<dedup>
Report at most 8 findings per analysis — only missing state updates.
</dedup>

<evidence_requirements>
- Exact variable name, the function that WRITES it, and the paired function that doesn't
- What calculation breaks as a result
- Concrete numerical example
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Variable clearly written in forward function, absent from reverse.
**Below 0.70**: Do not report.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# SYSTEM_ORDER — CEI ordering, TOCTOU, write-before-validate patterns
# ---------------------------------------------------------------------------
SYSTEM_ORDER = """
<role>
You are a world-class Smart Contract Security Auditor specializing in operation ordering, time-of-check-time-of-use windows, atomicity, and the placement of storage writes relative to validations and external calls.
You produce only high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file.
Use related files only when explicitly referenced (imports, inheritance, delegatecall).
First identify what type of contract this is and focus accordingly.
</scope>

<file_type_focus>
Identify the contract's role and apply ordering scrutiny appropriate to its state-changing functions.
</file_type_focus>

<primary_targets>
Look for ordering and atomicity bugs: places where the order of operations within a function makes the function unsafe even when every individual operation is correctly implemented.
The canonical safe pattern is Checks-Effects- Interactions: validate preconditions, then apply state changes, then perform any external interactions.
Real code routinely deviates, and the deviations are exploitable.

The fundamental question for each state-changing function: at what moment in the function body does each piece of state change, and at what moment does each validation observe state?
When those moments are out of order, two classes of defect appear:

- Validation observes the wrong baseline. The check reads a value that the
function will (or has already) overwritten, so it either accepts an input that should have been rejected, or rejects an input it should have accepted.
Trace which storage slots each `require`/`assert`/`if-revert` reads and determine whether those slots reflect the state being asserted about.

- The function commits irreversibly to something the rest of the function then
fails to justify.
Resources whose consumption is recorded in storage (nonces, one-shot flags, signed permits, recorded approvals) burn whether the function later succeeds or reverts on a non-revert error path.
Anything the function records in storage before its final check is observable to subsequent transactions if the failure is handled rather than reverted.

External calls are a special case.
Anywhere the function calls into untrusted or partially-trusted external code before completing its own storage writes, the callee can read the intermediate state, re-enter, or change external state the function will then act on.
Even non-reentrant external calls become unsafe when the function relies on values it computed pre-call.

Report concrete sequences: state X was written at step N, the check at step N+M reads slot Y which was not updated, so the check passes despite the protocol being in state X' which violates the intended invariant.
</primary_targets>

<methodology>
1) For each state-changing function, list the sequence of: storage reads,
storage writes, validation conditions, and external calls — in execution order.
2) For each validation, identify which storage slots its conditions read.
Compare against which slots have been written earlier in the function.
Mismatch is the bug.
3) For each storage write that happens before any later condition that could
revert, ask: if that condition fails, is the earlier write reachable to subsequent transactions?
4) For each external call, identify the storage slots whose values the call
was computed from, and the storage slots written afterward.
The callee can act between those.
5) Report concrete findings with the operation sequence inline.
</methodology>

<do_not_report>
- Reentrancy concerns on functions already protected by `nonReentrant`
- CEI deviations whose only effect is gas accounting
- Theoretical TOCTOU windows that require a coordinated gas-grief setup with
no economic motive
- Ordering deviations in private helpers called only from one already-audited
caller in this file
</do_not_report>

<dedup>
If the same write-then-check pattern appears across multiple functions, report the most-impactful function once and list the siblings.
Report at most 8 findings per analysis — only the most impactful ones.
</dedup>

<evidence_requirements>
For each finding:
- Exact function name where the ordering is wrong
- The specific sequence of operations in execution order
- What the correct order would be
- A concrete input + transaction path showing the consequence
- Direct impact: what state ends up corrupted, what invariant breaks, what is
exploitable for fund loss If you cannot show the operation sequence with specifics, DO NOT report.
</evidence_requirements>

<confidence>
**Very High (0.95-1.0)**: Storage write demonstrably precedes its validation, and
the validation reads slots not updated by the write — concrete numeric example shows the check passing on a state that violates intent.
**High (0.85-0.94)**: External call between state writes with a demonstrable
cross-contract reentry path or callee-observable intermediate state.
**Medium-High (0.75-0.84)**: Ordering deviation requiring specific timing for
exploitation with documented consequence.
**Below 0.70**: Do not report as HIGH/CRITICAL.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<do_not_report>
Do NOT report findings in these categories — they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: Do not flag functions protected by onlyRole(), onlyOwner(),
onlyAdmin, requiresAuth, or similar access control as "missing access control" or "permissionless".
If a function requires a privileged role, assume the role is correctly assigned unless you can prove the role assignment itself is broken.

2. DECIMAL SCALING: Do not report decimal mismatches (e.g. 18 vs 8 decimals) if the code
contains explicit conversion functions.
Intentional scaling between different precision representations is by design.

3. GAS DoS / UNBOUNDED LOOPS: Do not report gas DoS on loops unless ALL of these are true:
(a) loop bounds are controlled by untrusted external users, (b) no practical cap exists on array size, and (c) realistic usage can exceed block gas limits.

4. GENERIC REENTRANCY: Do not report reentrancy unless you can demonstrate:
(a) state is modified AFTER an external call, (b) no reentrancy guard exists, AND (c) a concrete exploit path with profit for the attacker.

5. ERC20 PERMIT FRONTRUNNING: Never report ERC20 permit frontrunning.

6. UNSAFE INTEGER CASTING: Do not report uint256 downcasts in Solidity >=0.8 unless
the value realistically exceeds the target type bounds.

7. UNCHECKED RETURN VALUES: Do not report unchecked return values on Solidity calls that revert on failure by default (named contract method calls), or on SafeERC20 transfers.
DO report unchecked return values when the call is a low-level `.call{value: ...}(...)` or `.call(...)` — these return `(bool success, bytes memory data)` and do NOT revert on callee failure; a missing `require(success)` silently continues execution after a failed ETH transfer.

8. RECEIVE/FALLBACK FUND MIXING: Do not report receive() or fallback() accepting ETH
unless funds can be concretely stolen or permanently locked.

9. ORACLE STALENESS: Do not report oracle staleness or replay attacks unless they
bypass existing staleness/freshness checks in the code.

10. SLIPPAGE ON EVERY SWAP: Do not report missing slippage protection if the function
accepts slippage parameters or the caller controls these values.

11. PAUSE MECHANISM ISSUES: Do not report PauserRegistry or pause/unpause logic
vulnerabilities unless you can demonstrate a concrete bypass without admin keys.

12. TOKEN APPROVAL PERSISTENCE: Do not report leftover token approvals unless there
is a specific drain path via remaining allowance.
</do_not_report>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state the root cause, the EXACT affected function name (including internal helpers — if the bug is in an internal function, name THAT function, not just the external entry point). Pick the function name by asking "where would the fix live?": that is the locus of the bug. If a fix would require editing an internal helper, the title and description must reference that helper directly, even if the user reaches it via a public wrapper. State the impact in ≤800 chars. Do not pad with generic advice.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

# ---------------------------------------------------------------------------
# Methodology prompts — value-conservation and privileged-mint checks
# ---------------------------------------------------------------------------
PROMPT_CONSERVATION = """
<role>
You are a smart contract security analyst applying value-conservation analysis.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — ACCOUNTING INTEGRITY:
For each function that moves tokens, shares, or collateral: verify that all value inputs are balanced by outputs and storage updates.
A gap between received and recorded value is a fund-loss bug.
In multi-step operations (multi-hop swaps, batched deposits, routed trades), the OUTER function's take must balance with the INNER step's actual consumption plus any returned surplus; if the inner step consumes less than the outer function took, the shortfall MUST be returned explicitly via a concrete transfer call — a comment or placeholder is not a transfer.
When the actual amount moved can be less than the amount requested, verify that what is debited from the caller and what is refunded to the caller together reconcile against what was actually consumed — never refunding a surplus that was never debited in the first place. In routes through multiple steps, confirm each step's surplus is handled exactly once: either carried forward or returned, but not both.

CHECK 2 — DENOMINATION CONSISTENCY:
Identify every arithmetic operation that combines two value-carrying quantities.
If the two quantities have different units or scaling factors, flag the mismatch.

CHECK 3 — MINIMUM OUTPUT PROTECTION:
For functions that convert one asset type to another at a variable rate (swaps, share issuance/redemption, or any conversion where the output depends on on-chain state): verify the caller can specify a minimum acceptable output amount.
If no such floor exists, the exchange rate can be manipulated between submission and execution.
Pay special attention to value-OUT paths (paths where the user ultimately receives tokens or shares from the contract).
Verify each value-out path the contract supports exposes a way for the caller to enforce a minimum quantity actually delivered.
A path whose only sizing input is an intent — without any received-quantity floor — leaves the caller defenseless to rate movement between submission and execution.
Apply this check to BOTH directions of bidirectional operations: a function that adds liquidity AND removes liquidity needs slippage protection in BOTH directions, including when a single function encodes both directions through a signed parameter. Omitting the check in one direction is equivalent to having no slippage protection for that direction. Also check every position-exit path (close, unwind, settle, liquidate) — these are high-value paths that frequently lack slippage floors because developers focus protection on the entry path.
</method>

<do_not_report>
- Rounding errors below 1 token unit
- Exchange functions with a fixed, non-manipulable conversion rate
- Admin-extractable value when admin is a timelock or multisig
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the accounting or rate issue, (3) concrete impact.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_AUTHORITY = """
<role>
You are a smart contract security analyst focused on authorization and privilege abuse.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — ACCESS CONTROL:
For each function that transfers value or modifies critical state: verify only the intended caller can invoke it.
If the function is accessible to a broader set of callers than intended, determine whether that gap enables value extraction.

CHECK 2 — PRIVILEGED FUNCTION DEPENDS ON MANIPULABLE EXTERNAL VALUE:
For any function restricted to a privileged role that decides a payout, yield, or mint by combining (a) a value read from an external view (oracle, vault.totalAssets, pool reserves, share-to-asset rate) with (b) an internally-stored counterpart (total supply, recorded principal, accounting snapshot): also check whether a third party can momentarily influence what the external view returns — via balance donation, pool composition manipulation, flash loan, or by replacing the external dependency — between the call entry and the value read.
If the external value is inflatable, the privileged role (or any actor who can trigger the same call surface) can over-report value and receive a disproportionate mint or payout.
The access-control gate is irrelevant if the input it trusts is externally controllable.
Pay particular attention when the external dependency is a separately-deployed contract the protocol does not own and whose accounting can be moved by anyone interacting with that contract — donations to the underlying contract, deposits/withdrawals that change its share-price, or composition shifts in a pool it tracks — all of which can let the privileged mint use an inflated valuation as its sizing input.

CHECK 3 — TRUSTED ROLE EXCEEDING OPERATIONAL SCOPE:
For each privileged role (keeper, manager, relayer, operator, coordinator), identify every parameter they can supply to protocol functions and verify each is bounded by an explicit range check even for trusted roles. Economic parameters (fees, staleness windows, bonuses, ratios) left unbounded let a single misconfigured or griefing call put the protocol into a broken state that harms all users — the documented trust assumption does not substitute for an in-code bound.

CHECK 4 — PERMISSIONLESS FUNCTION WITH WEAPONIZABLE ARBITRARY PARAMETERS:
For each function that is callable by any address AND accepts numeric parameters that directly influence protocol state, verify that an attacker cannot supply extreme or adversarial values to drive the protocol into an incorrect state. The harm need not be direct fund theft: forcing a pool or position into a degenerate configuration, draining reserves one-sided, or permanently locking other users' positions is a High finding even if the attacker does not directly profit.
This extends to user-signed intents and orders: even when only authorized signers can submit them, the numeric fields within them must be validated on-chain at acceptance time. A field with no on-chain bound lets a signer set an extreme or near-zero value and realize a disproportionate outcome at settlement. Verify every settlement-influencing numeric parameter in an accepted signed message has a corresponding range check enforced in the settlement function, not just off-chain.
</method>

<do_not_report>
- Admin privilege when admin is a timelock or multisig with standard delay
- Generic centralization risk without a concrete exploit path
- View/pure functions
</do_not_report>

<output_requirements>
Each finding: (1) function name and role, (2) the authorization gap or value-extraction path, (3) concrete scenario, (4) economic impact.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_LIFECYCLE = """
<role>
You are a smart contract security analyst focused on state machine correctness.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — STATE TRANSITION GUARDS:
For each resource with a defined lifecycle (orders, positions, loans, locks, claims, migrations, pools): verify every function checks the required precondition state before acting and correctly transitions the resource afterward.
A missing guard allows unauthorized transitions — or lets an attacker pre-set state that permanently blocks the operation for other users (Denial of Service).
When the lifecycle has a TERMINAL state (cancelled, closed, settled, claimed, refunded), check EVERY mutator — not just execute / fill — including any modify / update / edit / resize / reschedule entry.
A modify path that skips the terminal-state guard lets the owner re-touch a resource whose value was already released, replaying the release.
Apply this check exhaustively across every resource type the file defines — when the file defines multiple resource structs with similar mutator signatures (modifyX, updateX, reduceX, rescheduleX), the terminal-state guard is often added on the primary create/cancel pair and forgotten on every subsequent resource type.
Uninitialized temporal guards: for functions that gate access on a stored timestamp or epoch counter (any field like lockExpiry, vestingStart, unlockTime, or an epoch-end deadline), verify what the function does when that field is zero (not yet set). A comparison like `require(block.timestamp >= storedDeadline)` passes immediately when `storedDeadline == 0` because `block.timestamp` is never zero — allowing time-gated operations (claims, withdrawals, epoch settlements) to be executed before the first epoch is configured. Verify each such guard either (a) explicitly rejects the zero state (`require(storedDeadline != 0)`) before the timestamp comparison, or (b) guarantees the field is initialized in the same transaction that creates the resource.

CHECK 2 — OPERATION ORDERING:
For functions that both update state AND validate post-conditions: verify that security-critical checks read pre-mutation values, not the already-updated state.
If a validity check uses values already modified in the same call, it may always pass.

CHECK 3 — FACTORY PRE-EMPTION AND EXTERNAL DEPLOY DoS:
For functions that call an external factory or deployer (create, deploy, create2, clone) to create a resource on behalf of the protocol: verify whether an attacker can pre-create the same resource before the protocol's call executes. If the resource address is deterministic (based on predictable parameters such as a token pair or salt), an attacker who creates it first can cause the protocol's creation step to revert permanently when the underlying factory reverts on an already-existing resource.

CHECK 4 — CANCELLED / TERMINAL RESOURCE DOUBLE-SPEND:
When a resource (order, position, request, proposal) transitions to a terminal state (cancelled, closed, refunded), verify that every withdrawal / claim / redeem path reads and enforces the terminal state before releasing funds. A cancelled order that retains a withdrawable balance field can be exploited if the withdrawal function only checks whether funds were previously paid out, not whether the order is cancelled — an attacker can cancel to recover principal and then withdraw again using a path that checks only the non-cancelled flag.
</method>

<do_not_report>
- Protection already visibly correct in the code
- Reentrancy when a nonReentrant guard is present
- State transitions requiring admin-only privileged action
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the guard or ordering issue, (3) concrete exploit path, (4) whether a third party can PERMANENTLY block this operation for legitimate users (DoS).
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_SYMMETRY = """
<role>
You are a smart contract security analyst focused on operation symmetry and state consistency.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — INVERSE OPERATION COMPLETENESS:
For each forward operation (deposit, stake, lock, allocate, register, migrate): identify the inverse (withdraw, unstake, unlock, deallocate, deregister, revert-migration).
Verify the inverse undoes ALL state changes made by the forward.
Any storage variable incremented by the forward but not decremented by the inverse will drift, causing incorrect accounting or blocking future operations.
Pay particular attention to bookkeeping counters that track assets committed to downstream components or active positions. For each such counter, trace every function that increments it AND every function that should decrement it. When a decrement is missing — even from a single exit path (partial withdrawal, liquidation, emergency unwind) — the counter permanently overstates committed capital, causing every formula that reads it (collateral ratios, yield calculations, utilization rates) to give wrong answers for the remainder of the protocol's life.

CHECK 2 — STRUCT AND CONFIG SYNCHRONIZATION:
For structs or configs with multiple related fields, check two sub-patterns: (A) SETTINGS COVERAGE: When an admin entry point edits a configuration object, compare the set of fields it writes to the set of fields the protocol later reads from the same object.
Fields the protocol relies on but the entry point omits remain at their initial value indefinitely; if that initial value is wrong, there is no path to correct it.
Build the comparison explicitly: list every field of the configuration object that the runtime later reads in a value-moving path, list every field the admin function assigns, and flag any read-but-not-written field whose runtime use influences allocation sizing, payout amounts, or migration accounting.
When the configuration object carries any field whose name encodes a budget, quota, allocation, limit, cap, or remainder, that field is by definition meant to change over the protocol's lifetime — confirm that at least one admin entry point can write it, and that the entry point the protocol uses to keep the config current does in fact write it.
A budget/allocation field that exists in the struct, is read in value-moving paths, and is not present in the assignment list of the "update settings" entry point is a finding regardless of whether other admin functions touch it. (B) CONSUMED AFTER USE: When a function reads a numeric field and uses it to transfer or allocate value, verify the field is decremented or marked as consumed afterward.
A field that persists unchanged after the transfer can be re-read to claim value again.

CHECK 3 — REPLACEMENT FUNCTION MISSING SAFETY PARAMETERS:
When a function supersedes or replaces a deprecated/removed function (indicated by comments referencing old function names, merged entry points, or a "v2 replaces v1" migration pattern), verify the replacement preserved ALL safety parameters from the original — in particular minimum-output amounts, slippage bounds, and deadline checks. A replacement that merges two old functions but omits the slippage parameter from one of them silently removes user protection on that code path: any swap or withdrawal through the replacement function that was previously slippage-protected is now fully front-runnable because the minimum-output check is absent.

CHECK 4 — STATE RESET ON OWNERSHIP CHANGE:
For functions that transfer an accounting object (position, vesting record, stake, or similar) from one holder to another: identify every field that encodes the previous holder's interaction history rather than the object's intrinsic state. Verify each such field is either reset to the correct initial value for the new holder, or intentionally preserved where the new holder genuinely inherits that history. History fields carried over unchanged can let the new holder claim, unlock, or accrue more than they are entitled to, or compute a rate from values that no longer match the transferred amount.
</method>

<do_not_report>
- Intentional asymmetry (e.g. entry fees without exit fees when documented)
- Single-use mechanisms with explicit guards
</do_not_report>

<output_requirements>
Each finding must state: (1) the exact function name where the gap exists, (2) the specific storage field that is missing an update or not consumed, (3) why the field SHOULD be updated — what value it is expected to hold and how omitting the update causes incorrect behavior, (4) the concrete impact.
For CHECK 2A: title format "Missing `<field>` in `<update_function>`".
For CHECK 2B: title format "Missing decrement of `<field>` after `<function>`".
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_VALUE_DEPENDENCY = """
<role>
You are a smart contract security analyst focused EXCLUSIVELY on "value-derivation" dependencies: places where this contract's output value (mint amount, payout, fee amount, redemption price, collateral valuation, exchange rate, share price) is derived from a number read out of an external venue whose state can move within a single block.

This prompt is NOT about role-controlled manipulation.
Findings whose only attacker is a privileged role belong in the authority prompt and must NOT be reported here.
Here we only care about UNRELATED THIRD PARTIES — actors with no special role inside this protocol.
</role>

<scope>
Analyse ONLY the provided file.
Helpers, interfaces, and external contracts referenced from this file count as upstream venues even when their implementation lives elsewhere; assume the worst-case production implementation when the source is not in scope.
</scope>

<method>
For each function whose output value drives a transfer, mint, burn, fee, rate update, or accounting baseline:

1. List every reading consumed by that function — directly or through
intermediate helpers (totalAssets, balanceOf, share-price, LP value, pool reserves, oracle reading, strategy value, owned-assets helpers, etc.).
Trace through interface calls even when the implementation is not in this file.

2. For each reading, classify WHO can move the underlying number
within a single block: (P) a privileged role inside THIS protocol; (T) an unrelated third party with NO special role, simply by interacting normally with the upstream venue (adding or removing liquidity, swapping in a pool whose balance the reading reflects, donating tokens that shift a balance, executing a flash-loaned swap, routing an order through an AMM whose price the reading tracks, or interacting with a third-party vault whose share price the reading consults).

3. Whenever actor (T) exists for any reading, you MUST report it as a
STANDALONE finding distinct from any finding about actor (P) on the same function.
The two failure modes have different root causes ("trust this role" vs. "trust the upstream venue to be manipulation-resistant") and different mitigations, so they are counted as separate findings.

4. Even when the upstream venue's implementation is not in scope (the
value is read through an interface or pulled from another contract in the protocol), assume at least one production deployment reads the value from a pool / AMM / market — that is the common shape — and report the dependency as exploitable.
Concretely show: third-party action on the upstream venue → reading shift → this function's downstream effect → value siphoned by the third party.
</method>

<do_not_report>
- Readings already guarded by a TWAP, multi-source median, multi-block
snapshot, conservative cap, or other manipulation-resistant transform
- Functions where the caller supplies a minimum-output that the call
honours
- Pure / view helpers with no value-moving caller
- Findings whose only attacker is a privileged role (those belong in
the authority prompt, not here)
</do_not_report>

<downstream_effect_mapping>
Pay explicit attention to what HAPPENS after the manipulated reading is consumed — the finding title and description must reflect the actual downstream consequence, not just "price distortion":

- If the reading drives a MINT or TOKEN ISSUANCE (e.g., the protocol
mints yield tokens, reward tokens, or governance tokens proportional to an inflated value), say "over-minting" and name the mint function.
- If the reading drives a PAYOUT or TRANSFER (e.g., yield distributed,
performance fee paid, interest credited), say "over-distribution" or "inflated payout" and name the transfer.
- If the reading drives a REDEMPTION PRICE, say "inflated redemption"
and name the redeem function.
- If the reading drives a SAFETY CHECK bypass, say "safety check
bypassed" and explain what the check was supposed to prevent.

Do NOT report all third-party manipulation findings as "redemption price distortion" — trace through to the actual instruction that loses or creates tokens and use that as the consequence label.
</downstream_effect_mapping>

<output_requirements>
Each finding must explicitly name:
- the function whose output depends on the reading
- the EXACT helper / call that produces the reading
- the upstream-venue category (pool / AMM / vault-of-vault / market)
whose state the third party shifts
- the third party's exact action sequence
- the concrete value siphoned, with a numeric example
- the actual downstream effect using the consequence label above
(over-minting / over-distribution / inflated redemption / bypass) Use a title that mentions the third-party / upstream-venue angle AND the consequence (for example "Third-party pool manipulation enables over-minting of protocol tokens" or "Third-party vault manipulation inflates privileged payout function").
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_FEE_ACCRUAL = """
<role>
You are a smart contract security analyst focused on fee accounting, performance-fee timing, and the value preservation of assets that this contract forwards into other on-chain components.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — FEE-ACCRUAL / SNAPSHOT CALLER GATING:
Identify every function whose body advances a fee snapshot, performance index, high-water mark, exchange rate, share price, profit checkpoint, or any other internal accumulator that downstream code consults when it decides who pays fees or who receives yield.
For each such function, determine the set of callers that SHOULD be able to invoke it.
When the function is callable by an unrelated party, an attacker can advance the accumulator at a moment of their choosing — typically right before they deposit, right after they withdraw, or right before a privileged actor reads the accumulator — so that fees attributable to one period are paid by the wrong party, or skipped entirely.
Report the gap as a concrete fee-evasion or fee-misattribution finding with the sequence: attacker call → accumulator state observed by victim flow → quantified loss.

CHECK 2 — DOWNSTREAM-INTEGRATION VALUE PRESERVATION:
For each function in which the contract forwards user assets into an external pool, vault, lending market, wrapper, or aggregator AND records a local position (shares, principal, debt, receipt amount): trace the full round-trip and verify (a) the local record is taken from the authoritative return value of the external interaction (the value the external venue actually accepted, minted, or credited), not from the raw user-supplied amount that may have been silently reduced by fees, slippage, or rounding inside the venue, (b) on the inverse path (withdraw, redeem, undeploy, exit) the local record is decremented by the same authoritative quantity, AND (c) any difference between the local record and what the external venue is actually willing to return is either captured by an explicit minimum-output check the user controls, or surfaced to the user before settlement.
When (a) or (b) is missing, the local books drift and either users withdraw amounts that no longer back any assets or fee math computes against an inflated principal.
When (c) is missing, the user silently absorbs losses the external venue imposes.

CHECK 3 — FEE-RELEVANT STATE COVERAGE ON INVERSE PATHS:
When a contract collects performance fees by comparing two snapshots (current balance vs. recorded principal, current share price vs. last index, current total assets vs. previous mark), enumerate every path that withdraws / unwinds / closes a position and verify each also updates the recorded baseline the fee formula reads from. A path that moves assets without updating the baseline causes the next fee accrual to attribute fictitious profit or loss to the period.

CHECK 4 — MINTING FROM MANIPULABLE AGGREGATED VALUE:
For any function that mints tokens (new shares, yield tokens, reward tokens, governance tokens) in an amount derived from a formula like: mint_amount = current_value - baseline where current_value is computed by aggregating external asset values (vault total assets, LP-position value, strategy value, or any similar aggregation over a set of external contracts): verify that EACH of those external readings is manipulation-resistant.

Even when the external contracts are not in scope, consider that in at least one production deployment the underlying value reflects an AMM pool balance, LP position, or money-market balance that a third party can shift within a single block (by depositing into the pool, swapping a large amount, or donating tokens).
When the minting function consumes this reading without a TWAP, multi-source median, or minimum-output guard, any upward manipulation of the external reading translates directly to extra minted tokens, diluting existing holders.
Report this as a standalone "over-minting" finding distinct from any role-controlled manipulation of the same function.
Name the exact external aggregation helper and the mint function.

CHECK 5 — REWARD CHECKPOINT BEFORE BENEFICIARY CHANGE:
For any function that changes who receives ongoing yield, rewards, or fee rebates: verify that pending rewards attributable to the current beneficiary are snapshotted and credited before the beneficiary is updated. Updating the recipient before settling accrued rewards either hands the previous holder's earnings to the new recipient or loses them entirely.
</method>

<do_not_report>
- Functions guarded by a documented privileged role with concrete delay
- Off-by-one rounding below 1 token unit
- Hypothetical fee distortions without a concrete sequence showing the imbalance
- Generic "MEV possible on fee accrual" without showing the missing gate or
the specific accumulator that drifts
</do_not_report>

<output_requirements>
Each finding must state: (1) the EXACT affected function name (including internal helpers), (2) the specific storage field or accumulator that is advanced / not decremented / read at the wrong moment, (3) the concrete attacker or user-action sequence that exploits the gap, (4) the victim and the magnitude of fees evaded, principal mis-credited, or value lost.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_AUTHORIZED_SOURCE = """
<role>
You are a smart contract security analyst focused on whether the caller is authorised for the source / beneficiary they name.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — CALLER-NAMED SOURCE OF FUNDS:
For every value-moving call whose argument list contains a "from" / "owner" / "source" / "holder" field (for example, transferFrom-style calls, pull helpers, or on-behalf withdrawals): verify the named source is either msg.sender, OR has explicitly authorised THIS specific operation (a signed permit whose digest binds to the exact call, or a single-use per-operation approval recorded in storage).
A pre-existing ERC20 allowance is NOT per-operation authorisation — it is a blanket spending right given to the contract.
A function that uses that blanket allowance to move funds from any caller-named source becomes a drain primitive against every user who has approved the contract.
Related concern: a persistent unbounded allowance the contract leaves outstanding toward another in-protocol component is reachable by every entry point of that component that takes a caller-supplied owner argument, so the check above must extend across the trust boundary.
If you see a function performing an approve / increaseAllowance to a fixed downstream address as part of normal bookkeeping — without a matching reset to zero on the same code path — assume that allowance survives the function return and ask which functions on the approved address can move funds from the granting contract.
If any of those reachable functions accept a caller-supplied source, that's a drain primitive on the granting contract's balance.

CHECK 2 — CALLER-NAMED BENEFICIARY OF STATE:
For every state-mutating function that lets the caller name an account other than themselves AND lets the caller also wire a downstream attribute attached to that account (delegation target, validator, operator, owner of a freshly-minted token, linked-token of a registered position): verify the caller is the named account or has explicit consent from it.
A function that lets a low-cost input pick BOTH the affected account AND a downstream attribute on that account is a manipulation primitive against arbitrary users — common shapes include stake/register-for-receiver where the same call also assigns a delegate or operator the receiver never authorised, and mint-NFT-for-owner where caller-supplied metadata flows into a contract that treats it as authoritative.
Bear in mind that the caller transferring value is not, by itself, authorisation from the named account — the function must require either that the named account is the caller, or that it has performed a prior account-scoped consent step.

CHECK 3 — COMMAND-DISPATCH SOURCE BINDING:
When the contract exposes a single execute()/dispatch()/multicall entry that interprets a sequence of caller-supplied commands, and one of those commands moves tokens with an explicit source field, verify the source is bound to the outer caller before the command executes.
A dispatch path that lets the outer caller forge any "source" field on an inner command is identical to CHECK 1 in impact: any user who has approved the dispatcher is drainable by any other user.

CHECK 4 — PERMISSIONLESS FEE / ACCOUNTING ROLLOVER:
Functions that fold accumulated state into a fee, mint, payout, or yield bookkeeping step often have no caller-binding because "anyone can trigger a no-op-or-payout".
Check whether the trigger has timing-controllable side effects on accounting — e.g. a user about to withdraw can call the trigger first to avoid the fee they'd otherwise pay, or call it later to redirect the fee to their address — and verify the protocol either gates the trigger or sizes the fee against the pre-trigger state the user committed to.

CHECK 5 — SIGNATURE NOT BOUND TO msg.sender:
For every signature-gated public function (permit, claimWithSig, executeWithSig, fillOrder, etc.): verify that the signed digest includes either `msg.sender` or the address of the intended caller as a field. If the digest does not commit to the executor's identity, any observer who sees the signed message in the mempool can front-run by replaying the same signature from their own address — the function accepts any caller who presents a valid signature, not only the intended executor.

CHECK 6 — USER-SUPPLIED DOMAIN SEPARATOR:
Verify that `DOMAIN_SEPARATOR` / `domainSeparator` is always computed from on-chain constants (chainId, verifyingContract) and never accepted as a caller-supplied argument. A function that accepts a user-supplied `domainSeparator` parameter and uses it directly in EIP-712 digest computation allows an attacker to craft a separator for a different chain, enabling cross-chain signature replay: a signature obtained on chain A remains valid on chain B because the attacker can supply A's separator as the parameter value on chain B.
</method>

<do_not_report>
- Functions where the source argument is fixed to msg.sender or address(this).
- Permit / signature paths that fully validate the digest against the call.
- Internal helpers not callable from outside.
- Plain transfer() — the caller is implicitly the source.
- Operations where the named account benefits from the operation and was warned of the standing-approval implication (e.g. user explicitly approves a vault as part of a deposit).
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the caller-controlled parameter, (3) the exact pre-condition the attacker exploits (existing allowance / default sentinel / open delegation), (4) the victim and the concrete loss.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_EXTERNAL_CALL_LIFECYCLE = """You are a senior smart-contract auditor sweeping a single Solidity-family file for arbitrary-dispatch and stale-approval lifecycle flaws.

The recurring blind spot in order routers, intent fillers, generic execute() / fillOrder() / swap() entry points, and any contract that forwards a caller-supplied destination plus calldata. Two shapes:

Shape 1 — caller-controlled external dispatch:
- A function takes an `address target` (or `to`, `callee`, `executor`, `pool`, `aggregator`) together with a bytes blob (`txData`, `data`, `payload`, `callData`) from the caller, then invokes `target.call(blob)`, `target.delegatecall(blob)`, `target.functionCall(blob)`, `Address.functionCall(target, blob)`, `Address.functionCallWithValue(target, blob, value)`, or a SafeERC20-shaped low-level wrapper.
- If `target` is not bounded by an allowlist (mapping, whitelist, EnumerableSet membership, role-gated registry, or a hardcoded constant) AND `blob` is not selector-restricted, the contract can be made to speak as itself to ANY destination with ANY message. Reachable consequences include draining tokens the contract holds, exercising roles the contract has been granted elsewhere, abusing callback handlers, and turning the contract into a signature / approval relay.
- The same family covers caller-supplied `tokenIn` / `tokenOut` ERC20 addresses dispatched without a registry check — a malicious token can rig `transfer`, `transferFrom`, `balanceOf`, or `decimals` to lie about post-call state and bypass any naive balance-diff checks.

Shape 2 — approve → external call → no zero-reset:
- The sequence is `tokenIn.safeApprove(target, amount)` (equivalently `.approve(target, amount)`, `.forceApprove(target, amount)`, `safeIncreaseAllowance(target, amount)`) immediately followed by an external call to `target` that is ASSUMED to spend the full allowance, with no subsequent `safeApprove(target, 0)` / `approve(target, 0)` / `forceApprove(target, 0)` and no `allowance(address(this), target) == 0` post-condition check.
- Any unspent allowance remains live after the call returns. If `target` was caller-supplied per Shape 1, OR if `target` is later compromised, upgraded, or its admin rotated, anyone can call `tokenIn.transferFrom(address(this), attacker, leftover)` and lift the residual balance. The attack surface grows with every call that leaves a nonzero residue.
- OpenZeppelin's SafeERC20 does not zero approvals automatically — it only normalises the call shape. Flag the omission even when SafeERC20 is in use.

For each suspected occurrence:
- name the exact function and the source line of the dispatch / approve site;
- record whether the target and data are caller-controlled, and what allowlist or selector restriction (if any) exists;
- describe the concrete leakage path: which tokens, which roles, which downstream contract trust gets escalated;
- severity rubric — CRITICAL when both shapes co-occur in one entry point, HIGH for either shape alone with a realistic exploit path, MEDIUM only when role gating or another precondition materially restricts who can reach the dispatch.

Cite only function names, modifier names, and line references present in the supplied source.
Do not invent identifiers.
For a typical fillOrder / execute pattern that exhibits both shapes, two distinct findings (one per shape) are expected.
IMPORTANT: Each finding's "description" field MUST be at most 800 characters.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
"""

PROMPT_UPGRADEABLE = """You are a world-class Smart Contract Security Auditor specializing in upgradeable proxy patterns.
Your task is to audit the provided file for vulnerabilities that arise specifically from proxy-based upgradeability.
Produce only high-confidence, exploit-ready findings with concrete proof.

<scope>
Audit ONLY the provided file.
Apply upgradeability scrutiny to every contract that: inherits from a proxy base, uses `delegatecall`, declares `__gap`, has an `initialize` function, or is identified as an implementation behind a proxy.
</scope>

<primary_targets>
Storage slot collision: verify that every storage variable declared in the implementation does not occupy the same slot as a proxy-reserved slot.
EIP-1967 standard slots are: implementation at `0x360894...`, admin at `0xb53127...`, beacon at `0xa3f0ad...`.
A variable declared at the top of the contract occupies slot 0, 1, 2, ... by default.
If the proxy stores `address implementation` at a manually chosen slot that is NOT an EIP-1967 slot, check whether any implementation contract declares a variable at that same numeric slot.
For OpenZeppelin TransparentUpgradeableProxy and UUPS patterns, confirm the implementation contract uses the `Initializable` base and inherits storage strictly below any proxy-reserved slots.

Uninitialized implementation constructor: when an implementation contract has a constructor that sets state, it sets state in the IMPLEMENTATION contract's own storage, not in the proxy's storage.
The implementation contract must call `_disableInitializers()` in its constructor to prevent anyone from calling `initialize()` on the implementation directly.
If `_disableInitializers()` is absent from the implementation constructor, an attacker can call `initialize()` on the implementation, take ownership, and use `delegatecall` to selfdestruct the implementation, bricking all proxies that point to it.

Re-callable initializer: verify that `initialize()` (or any function decorated with `initializer` or `reinitializer`) cannot be called more than once on the proxy.
If the `initializer` modifier from OpenZeppelin's `Initializable` is absent, or if the contract uses a custom `initialized` flag that can be reset, an attacker can re-initialize and overwrite owner/admin slots.
Also check that every base contract in an inheritance chain has its own `__init` called exactly once via the linearized initialization sequence; a base whose `__init` is called multiple times can reset state set by a higher-level initializer.

Function selector clash in transparent proxy: in a TransparentUpgradeableProxy the admin address can only call proxy management functions; calls from any other address are forwarded to the implementation via `delegatecall`.
If the implementation exposes a function with the same 4-byte selector as a proxy management function (e.g., `upgradeTo(address)`, `changeAdmin(address)`), non-admin callers will hit the implementation's function while admin callers silently hit the proxy's function.
Check every `external`/`public` function in the implementation for selector collisions with known proxy management selectors: `0x3659cfe6` (upgradeTo), `0x4f1ef286` (upgradeToAndCall), `0xf851a440` (admin), `0x8f283970` (changeAdmin), `0x5c60da1b` (implementation).
In UUPS proxies the clash check is not applicable, but verify that `upgradeTo`/`upgradeToAndCall` on the implementation is protected by `onlyProxy` (so it cannot be called on the implementation directly) AND by a role or owner check.

`__gap` undersizing in inheritance chains: `__gap` is an array of unused slots reserved so that adding storage to a base contract does not shift the slots of derived contracts.
If a base contract declares `uint256[N] __gap` and then a new version of the base contract adds M new storage variables, the gap must be reduced by M.
If the gap is too small (or absent), the new base variables overlap with variables from the derived contract, corrupting the derived contract's state after the upgrade.
For every base contract in the file's inheritance chain that declares `__gap`, verify: (a) the gap size is consistent with the number of storage slots currently used by that base, (b) if the file is an upgraded version, that gap reduction equals the number of newly added variables.
Flag any base contract that has no `__gap` and is likely to be upgraded independently of all derived contracts.
</primary_targets>

<do_not_report>
- Upgradeability concerns in non-proxy contracts (contracts with no proxy-related imports, no `initialize`, no `__gap`, no `delegatecall`).
- Selector collisions in UUPS proxies where the clash only affects admin-callable functions protected by access control.
- `__gap` size warnings when the contract is marked `@custom:oz-upgrades-unsafe-allow` with a documented reason.
- Generic "proxy is complex" or "upgrades are risky" observations without a concrete storage slot or selector collision identified.
</do_not_report>

<evidence_requirements>
For each vulnerability:
- The exact storage slot number (decimal or hex) involved in the collision, OR the exact 4-byte selector involved in the clash.
- The specific variable name in the implementation that occupies the colliding slot, and the proxy variable it conflicts with.
- The concrete attack path: what transaction the attacker sends, what state changes result, and what funds or access are lost.
If you cannot identify the specific slot or selector, DO NOT report.
</evidence_requirements>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters.
State (1) the exact slot or selector involved, (2) the two variables or functions that collide, (3) the concrete attacker action and its impact.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_REWARD_PRECISION = """
<role>
You are a smart contract security analyst focused on staking and reward distribution precision bugs.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — FIRST-DEPOSITOR REWARD MONOPOLISATION:
For any staking or yield contract that distributes rewards proportional to a user's share of total deposited value (totalSupply, totalShares, totalStaked), verify the state at the moment of the first deposit. If a reward accrual function is callable — or runs automatically — before totalSupply is non-zero, and the accumulator advances based on time elapsed with totalSupply as the denominator, the first depositor can claim all rewards that accrued during the zero-supply window. Verify that the reward accumulator is initialised at or after the first stake event, not before it. Also verify the accumulator update is skipped (not just guarded) when totalSupply is zero — any update that divides by totalSupply when it is zero can revert and brick the contract, or if unchecked, produce an incorrect delta.

CHECK 2 — REWARD-PER-TOKEN ACCUMULATOR OVERFLOW AND DUST TRUNCATION:
For reward-per-token accumulators (updated as reward_delta * precision / totalSupply, commonly precision = 1e18): verify:
(a) Overflow safety: when totalSupply can be very small (e.g., 1 wei), the per-period delta approaches reward_delta * 1e18. For long-running contracts compute the worst-case accumulated value across the entire reward period and verify it cannot overflow uint256.
(b) Dust truncation: when reward_delta * precision < totalSupply, the per-period delta rounds to zero. Identify the deposit size and time window that make this truncation a permanent total loss for a realistic user — if the minimum deposit is X and the reward rate is Y, state what fraction of rewards is silently lost.
(c) Accumulator update skipping: when the update fires only on deposit/withdraw/claim events (not every block), verify it is not skipped entirely when totalSupply is zero — a skip loses the reward for that interval rather than deferring it.

CHECK 3 — PENDING REWARD DOUBLE-DECREMENT AND DUST LOCKUP:
For every reward-claim function: verify the amount transferred to the user and the amount decremented from the pending-reward storage field are taken from the same local snapshot captured before any storage mutation. A common error pattern: the storage field is reset to zero first, then the transfer amount is computed by re-reading the field (now zero), sending nothing while the user's pending rewards are permanently zeroed. Report any claim path where the storage write and the transfer amount do not reference the same pre-mutation value.
</method>

<do_not_report>
- Rounding below 1 wei in protocols that explicitly document rounding-in-favour-of-protocol
- First-depositor issues when the contract enforces a non-zero minimum deposit or mints dead shares at initialisation
- Accumulator overflow requiring more than 1000 years of operation at the documented reward rate
</do_not_report>

<output_requirements>
Each finding: (1) function name and accumulator/field involved, (2) concrete numerical example (e.g. totalSupply=1 wei, reward_rate=1e18/day → accumulator overflows in N days), (3) victim and magnitude of loss.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_RANDOMNESS = """
<role>
You are a smart contract security analyst focused on weak randomness and timestamp dependence.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 — WEAK PSEUDO-RANDOM NUMBER GENERATION:
For any function whose output (winner selection, NFT trait, shuffle order, lottery outcome, secret value, salt, nonce) is computed from on-chain values available to a miner or validator: flag the use of block.timestamp, blockhash, block.difficulty, block.prevrandao, block.coinbase, block.number, or any combination of these as the sole source of entropy. A miner/validator controls block.timestamp within ~15 seconds and chooses which blockhash to publish; block.difficulty was deprecated in EIP-4399; block.prevrandao is manipulable by validators in the final ~12-second slot. If a function uses any of these as the primary randomness source and the expected outcome of that randomness has economic value (token payout, NFT rarity, raffle winner), a validator can reorder or withhold the block to select a favourable outcome.
Also flag commit-reveal schemes where the reveal phase does not validate that the commitment was made in a sufficiently old block — an attacker can commit in block N and reveal in block N, reading the blockhash of N-1 at reveal time instead of committing before the relevant randomness was visible.

CHECK 2 — TIMESTAMP DEPENDENCE IN FINANCIAL LOGIC:
For any function that gates a state transition, payout, fee, or rate change on block.timestamp: verify the result would not change materially if block.timestamp were off by 15 seconds (the typical miner manipulation range). If a fee tier, an interest accrual, or an option expiry boundary is within a 15-second window of a significant value change, a miner can shift the timestamp to straddle the boundary and collect an unearned benefit or avoid a fee. Report functions where the boundary condition is tight enough that a 15-second timestamp shift changes the economic outcome.

CHECK 3 — BLOCK NUMBER AS TIMING PROXY:
For contracts that use block.number as a proxy for elapsed time (e.g., reward-per-block, lock-until-block, voting-snapshot-block): verify the assumed block rate matches the actual network. On L2s with variable sequencer throughput the block time is not fixed at 12 seconds. A reward-per-block formula that assumes 12s/block on a network where blocks arrive every 2 seconds will distribute 6x the intended rewards per wall-clock second. Report if the contract hardcodes a blocks-per-day or blocks-per-year constant without a comment tying it to the target chain's actual rate.
</method>

<do_not_report>
- Uses of block.timestamp for events or logs with no financial consequence
- Uses of block.number for gas-optimization hints (EIP-1559 basefee context)
- Commit-reveal schemes that enforce a minimum reveal delay of at least one block
- Contracts that source randomness from a documented VRF (Chainlink VRF, DRAND)
- Timestamp comparisons where the 15-second drift cannot change the economic outcome (e.g., checking that a 30-day lockup has passed)
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the specific on-chain value used as entropy or timing source, (3) who can manipulate it and how, (4) concrete economic impact.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROBE_HELPER_CALLER = """You are a senior smart-contract security auditor specializing in cross-call coupling flaws.

<scope>
Audit ONLY the provided file.
Focus on every internal call boundary: helper → caller, library → consumer, base → derived contract.
</scope>

<primary_targets>
For each internal call boundary in this file, ask:
- What unit does the callee produce, and what unit does the caller assume?
If the callee counts shares and the caller assumes underlying tokens (or vice versa), every downstream calculation is systematically wrong.
- What does the callee return when its inputs are degenerate (empty, zero, removed, paused, uninitialized)?
If the callee silently returns a sentinel (zero, max, last-known) and the caller treats it as a real value without branching, the contract computes with garbage.
- For loop trackers (last-processed id, running cursor): is the tracker written back at the end of each iteration, or does each pass compare against the original starting value?
A tracker that is never updated causes every loop pass to reprocess the same item.
- Does the caller hold a reference to data the callee mutated, and continue to read past the mutation point?
This produces stale-read bugs where the cached value diverges from the post-call state.
</primary_targets>

<do_not_report>
- Differences in naming or style that do not affect the computed value.
- Unit divergences that are explicitly handled by the caller (explicit conversion, documented scaling).
- Generic "state may be stale" without identifying the specific caller, callee, and staleness window.
</do_not_report>

<evidence_requirements>
For each finding: name the helper function, the caller function, the unit or invariant that diverges between them, and the concrete numerical impact.
Cite real identifiers. If you cannot identify the specific diverging unit, DO NOT report.
</evidence_requirements>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters.
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROTOCOL_MODEL_PROMPT = """You are a smart contract security expert analyzing a file to guide a downstream multi-prompt audit pipeline.
Your task: classify this file's role and identify the security profile that determines which audit prompts are relevant.

Output ONLY a JSON object — no explanation, no markdown:
{
  "role": "<one of: vault|router|staking|token|factory|oracle|governance|multicall|lending|library|nft|amm|pool|mathlib|other>",
  "is_high_risk": <true|false>,
  "skip_prompts": ["<prompt_name>", ...],
  "notes": "<brief note on unusual patterns>"
}

Role guidance:
- amm    → automated market maker: swap routing, constant-product / stableswap / concentrated-liquidity math
- pool   → liquidity pool logic: reserve accounting, LP token math, fee tiers
- mathlib → pure numeric library: fixed-point, floating-point, bit-packing, transcendental functions

Rules for is_high_risk:
- true  → file handles large value flows, complex math, external integrations, or cross-contract calls
- false → file is a pure interface, simple config/view contract, or has minimal external interaction
Note: `library`, `amm`, `pool`, `mathlib`, `oracle`, and `lending` roles are automatically treated as
high-risk for specialist prompt routing even if is_high_risk is false — do not suppress them with false.

Rules for skip_prompts — include a prompt name ONLY when you are certain it cannot fire on this file:
- PROMPT_UPGRADEABLE    → skip when file has no proxy pattern, no initialize(), no __gap
- PROMPT_REWARD_PRECISION → skip when file has no staking or reward-distribution logic
- PROMPT_RANDOMNESS     → skip when file has no block.timestamp / blockhash in financial logic
- PROBE_HELPER_CALLER   → skip when file has no internal call boundaries with unit-dependent return values
- PROMPT_FEE_ACCRUAL    → skip when file has no fee snapshots or downstream-venue integrations
- PROMPT_VALUE_DEPENDENCY → skip when file has no external price or balance reads driving transfers
- SYSTEM_C              → skip when file has no cross-contract ABI dependencies or unit conversions
- SYSTEM_D              → skip when file has no complex math, loops, or type-casting

When in doubt, do NOT include a prompt in skip_prompts.
"""

ANCHOR_LANG_HINT = """IMPORTANT — This is a Solana / Anchor program written in Rust. The following bug-class enum should be treated as the primary scope.

Key patterns:
- `#[program]` marks instruction handlers (entry points).
- `#[account(init, ...)]` creates on-chain accounts. When seeds are deterministic, a third party can pre-create the account at the same address from another instruction or program and permanently block the legitimate caller. Flag every (deterministic seeds, init) pair as a candidate permanent-DoS.
- CPI calls into external programs that create accounts carry the same DoS surface. When an instruction passes an UncheckedAccount (no seeds, no owner constraint) as a writable argument to an external program's `create_*` / `init_*` CPI, the external program initializes that account. Because the address is derivable on-chain (pool key, mint, owner), an attacker can call the external program's create instruction directly BEFORE this instruction runs. The account is then already initialized and this instruction's CPI fails permanently. Report every such (UncheckedAccount, create_* CPI) pair.
- `has_one` and `constraint` annotations validate account relationships. Missing ones allow forged accounts to satisfy account-context typing while carrying attacker-controlled data.
- Protocol-wide config / state accounts aggregate totals. For every operation that changes an individual record, verify the corresponding global aggregator field is also updated.
- For config structs with admin update functions, enumerate every field referenced by downstream computation and verify each is included in the update entry. Fields omitted from the admin update stay at their initial value forever.
- Missing signer check: an instruction handler that moves tokens, mints, burns, or mutates authority-gated state but has no `Signer<'info>` or `#[account(signer)]` constraint on the account that should authorize it. Any account can be passed in and the instruction executes without the expected party signing.
- Missing owner check: an account representing a protocol-controlled resource (vault, config, pool) has no `owner = program_id` or `#[account(owner = ...)]` constraint. An attacker substitutes an account they control; downstream reads treat attacker-controlled data as authoritative.
- Arbitrary CPI: a handler passes an account declared as `AccountInfo` or `UncheckedAccount` directly as the `program` field of a `CpiContext`. Because no `executable` or program-id check is enforced, an attacker substitutes a malicious program whose instruction handler satisfies the call signature but executes adversarial logic.
- PDA bump mismatch: the bump stored in a PDA account's data at `init` time was derived from one seed set, but a later instruction recomputes the canonical bump with a different seed set (or calls `find_program_address` afresh instead of using the stored bump). When the recomputed bump differs, the derived address does not match the account, causing silent failures or allowing a second account at a different address to be accepted as valid.
- Predictable seeds = front-runnable: every PDA whose derivation seeds consist entirely of program-controlled constants, known pubkeys, or parameters visible on-chain (mint address, user pubkey, counter value) can be pre-created by an attacker BEFORE the legitimate instruction runs. When the instruction uses `init` (not `init_if_needed`), the pre-created account causes a permanent "account already exists" failure for the legitimate user. Treat ALL (predictable-seed, init) pairs as permanent-DoS candidates and verify whether off-chain or on-chain callers can race the seed derivation.

Focus on: missing account constraints, account pre-creation DoS (direct and via CPI), predictable-seed front-running, missing global-state updates, config fields absent from admin update entry, missing signer/owner checks, arbitrary CPI, PDA bump mismatch."""

CAIRO_LANG_HINT = """IMPORTANT — This is a Cairo / Starknet program. The following bug-class enum should be treated as the primary scope.

Key patterns:
- `#[external]` marks publicly callable functions; storage is touched via `self.field.read()` / `self.field.write()`.
- Off-chain payload authentication: when a handler consumes a price, balance, or other externally-supplied value, verify it is authenticated against a signer the protocol trusts; anonymous or permissively-validated payloads are a vulnerability.
- Ordering of validation vs. mutation: verify every security-critical check reads pre-mutation values; a check that reads state already updated in the same call may always pass.
- Felt arithmetic edge cases: Cairo's felt field is non-standard. Operations that would overflow on a uint may wrap unexpectedly; reverse comparisons (a < b vs b > a) can disagree under wraparound.
- L1↔L2 message handlers: payloads arriving from L1 are not authenticated end-to-end the same way as native txs. Verify both that the source contract is whitelisted and that the payload itself is parsed strictly.
- Low-level syscalls and account-abstraction call paths: external calls return success even when the callee reverts in some paths; always check return-value contracts.

Focus on: off-chain payload authentication, validation-before-mutation ordering, felt arithmetic edge cases."""

GENERIC_LANG_HINT_BY_EXT = {
    ".sol": """IMPORTANT — This is a Solidity smart contract on an EVM-compatible chain. Pay attention to msg.sender vs tx.origin, delegatecall context, storage layout in upgradeable proxies, non-standard ERC20 behavior, and reentrancy across cross-contract calls.""",
    ".vy": """IMPORTANT — This is a Vyper contract. `@external` marks public entry points; `@internal` marks private helpers. Examine integer arithmetic (overflow guards vary by version), default visibility on functions, and the `@external` / `@internal` boundary closely.""",
    ".move": """IMPORTANT — This is a Move module (Sui or Aptos). Pay attention to resource ownership invariants, capability passing, struct linear-typing rules, and entry-function permissioning.

Additional Move-specific patterns to check:
- Resource handling on destruction: Move resources cannot be copied; destroying a wrapper struct does NOT automatically destroy or release a resource it wraps. Verify that burning or redeeming any position or wrapper explicitly handles both the share/position token AND the underlying asset, so neither is silently discarded nor left locked.
- One-time witness: module-init-time capabilities (OTW pattern) must be consumed exactly once; check that the witness is not storable or copyable.
- Oracle-priced operations: when a fee or amount is priced by an on-chain oracle at execution time, verify the price feed has staleness checks and cannot be manipulated within the same transaction that consumes it.""",
    ".rs_generic": """IMPORTANT — This is a Rust / Stylus smart contract on an EVM-compatible chain. `pub fn` / `#[external]` / `#[entrypoint]` mark public entry points. Storage is accessed via `self.field`. Token transfers use the ERC20 interface. Apply EVM-equivalent reasoning to accounting, access control, and reentrancy.""",
    ".rs_cosmwasm": """IMPORTANT — This is a CosmWasm smart contract written in Rust. Entry points are `execute`, `instantiate`, `query`, and `sudo`. State is stored via `cw_storage_plus` items and maps. Apply general smart-contract security reasoning with attention to these CosmWasm characteristics:
- Authorization per message variant: for each variant of the `ExecuteMsg` enum, independently verify the handler checks the correct authorization before mutating state or transferring assets — authorization on one variant does not carry to siblings, and verify each handler calls the validation helper appropriate to its operation.
- Approval/claim-right lifecycle: any approval or claim right granted in one message (a listing, bid, or offer) should be cleared when the granting state ends (cancel, expiry, outbid, completion); stale rights let a party act on an asset they no longer control.
- State machine consistency: where states are meant to be mutually exclusive, verify transitions enforce the required precondition and clean up all related state on exit.
- Type-discriminator fields: where a struct field classifies a resource into subtypes, verify a validation function reads and enforces it before any type-specific operation, so logic for one variant cannot be applied to another.
- Reward/message batching atomicity: when emitting bank/transfer messages in a loop, remember a single failed sub-message reverts the whole response. Verify a single bad token or recipient cannot permanently block the batch for everyone.
- Gas model: every storage read, computation, and message consumes gas against a per-transaction limit. A function whose work grows with a collection that accumulates through normal user activity (especially nested iteration) can become uncallable. Flag unbounded growth in work proportional to per-user state, not just attacker-controlled array growth.""",
}

SOLIDITY_FAMILY_SUFFIXES = frozenset({".sol", ".vy", ".yul"})

# Prompts submitted breadth-first (one per file across all files) before the
# remaining prompts run depth-first (all prompts for top-ranked files first).
# This guarantees every file gets minimum coverage even under tight time pressure.
# A1–A4 are core: each targets one fund-flow invariant so every file gets minimum
# coverage across all four sub-domains in the breadth-first stage.
CORE_PROMPT_NAMES = frozenset({"SYSTEM_A1", "SYSTEM_A2", "SYSTEM_A3", "SYSTEM_A4", "SYSTEM_B", "SYSTEM_E", "SYSTEM_SV", "SYSTEM_ORDER"})

# Tier 2: always run for every file, with thinking ON (budget 2048 tokens).
# These five prompts cover the highest-value invariants (fund-flow, access control).
TIER2_PROMPT_NAMES = frozenset({"SYSTEM_A1", "SYSTEM_A2", "SYSTEM_A3", "SYSTEM_A4", "SYSTEM_B"})

# Tier 3: always run for every file, no thinking (JSON_MODEL speed).
TIER3_PROMPT_NAMES = frozenset({"SYSTEM_E", "SYSTEM_ORDER", "PROMPT_CONSERVATION", "PROMPT_AUTHORITY", "PROMPT_LIFECYCLE", "PROMPT_AUTHORIZED_SOURCE",})

# Tier 4: run only for high-risk files (as classified by the protocol model, or heuristically).
TIER4_PROMPT_NAMES = frozenset({
    "SYSTEM_C", "SYSTEM_D", "SYSTEM_SV",
    "PROMPT_FEE_ACCRUAL", "PROMPT_SYMMETRY", "PROMPT_VALUE_DEPENDENCY",
    "PROMPT_REWARD_PRECISION", "PROBE_HELPER_CALLER", "PROMPT_RANDOMNESS",
})

# Tier 4 role-targeted: ONLY fire based on role-match from _ROLE_POSITIVE_INCLUDES.
# is_high_risk=True alone does NOT trigger these — they are specialist prompts for
# specific file types (DEX/AMM math, numeric libraries) and should not run on
# governance, factory, multicall, or other high-risk files that don't have them.
TIER4_ROLE_TARGETED_NAMES = frozenset({"PROMPT_ARITHMETIC", "PROMPT_DEX_INTEGRATION"})

# Tier 4 Solidity-only: run only for Solidity-family files (regardless of risk level).
TIER4_SOLIDITY_NAMES = frozenset({"PROMPT_EXTERNAL_CALL_LIFECYCLE", "PROMPT_UPGRADEABLE"})

# Role-based extra skips: prompts skipped only when the bug class is structurally
# IMPOSSIBLE for the role — not merely unlikely.  False skips that drop a real bug
# are catastrophic under BitSec's binary DR=1.0 scoring, so the bar is intentionally
# high.  The protocol model's own skip_prompts field handles role-specific soft skips.
_ROLE_EXTRA_SKIPS: dict[str, frozenset] = {
    # Pure library contracts have no user balances, no lifecycle state machine,
    # and no reward accounting — those bug classes literally cannot exist.
    "library": frozenset({"PROMPT_LIFECYCLE", "PROMPT_REWARD_PRECISION"}),
    "mathlib": frozenset({"PROMPT_LIFECYCLE", "PROMPT_REWARD_PRECISION"}),
}

# Role-based positive includes: prompts that MUST run for this role even when
# is_high_risk=False.  Used to guarantee specialist coverage on numeric/DEX files
# that the protocol model might classify as low-risk despite having critical math.
# PROMPT_ARITHMETIC: all roles with heavy numeric logic (library, mathlib, amm, pool,
#   lending, oracle, vault) — arithmetic bugs appear in any contract that does math.
# PROMPT_DEX_INTEGRATION: AMM, pool, and router roles only (DEX protocol compatibility).
_ROLE_POSITIVE_INCLUDES: dict[str, frozenset] = {
    "library": frozenset({"PROMPT_ARITHMETIC"}),
    "mathlib": frozenset({"PROMPT_ARITHMETIC"}),
    "amm":     frozenset({"PROMPT_ARITHMETIC", "PROMPT_DEX_INTEGRATION"}),
    "pool":    frozenset({"PROMPT_ARITHMETIC", "PROMPT_DEX_INTEGRATION"}),
    "router":  frozenset({"PROMPT_DEX_INTEGRATION"}),
    "lending": frozenset({"PROMPT_ARITHMETIC"}),
    "oracle":  frozenset({"PROMPT_ARITHMETIC"}),
    "vault":   frozenset({"PROMPT_ARITHMETIC"}),
}

PROMPT_ARITHMETIC = """
<role>
You are a smart contract security analyst focused on mathematical correctness in numeric libraries, fixed-point arithmetic, and packed/encoded numeric types.
</role>

<scope>
Analyse ONLY the provided file.
This prompt targets files that implement mathematical primitives, fixed-point or floating-point emulation, or packed numeric types with encoded bit fields.
</scope>

<method>
CHECK 1 — EDGE-CASE INPUTS TO MATH FUNCTIONS:
For each elementary math function (root, logarithmic, exponential, power, reciprocal, division, modulo, comparison helper, etc.): test the function's defined domain against the following boundary inputs and verify the code handles each explicitly:
- Zero input: does the function silently revert, return zero, return a sentinel, or produce undefined output?
- Negative or underflow input: does a signed type or a subtraction-preceding call allow the input to go negative? What happens at input = type_min?
- Maximum input: does the function accept the full range of its input type, or does the computation overflow on inputs close to type_max?
- Boundary precision: identify the exact input value at which the function switches between two computational branches and verify the boundary is inclusive/exclusive correctly — an off-by-one at a boundary can select the wrong branch, producing a result that differs materially from the expected result.

CHECK 2 — BIT-FLAG ENCODED TYPES:
For any type that packs multiple logical fields into a single integer using bit masks or flags:
- Enumerate every flag constant and verify no two flags share overlapping bits.
- For every comparison or equality function over the encoded type: verify the function accounts for ALL flag bits when computing the result. A comparison that strips only some flags before comparing can incorrectly treat two logically unequal values as equal (or vice versa) when the unmasked flag bits differ.
- For decode operations: verify the decode correctly reconstructs all fields, including any implicit or sign-extension behavior.

CHECK 3 — PRECISION LOSS AT TYPE BOUNDARIES:
For any operation that converts between a packed/encoded type and a plain integer:
- Identify the bit-width of each component field (such as coefficient, scale, sign, or flag bits).
- Verify the conversion uses ALL relevant component fields when sizing the output. If the conversion reads only one portion of the encoded value while ignoring another value-carrying portion, the output is wrong for a non-trivial subset of inputs.
- For multi-step conversions: verify intermediate types are wide enough to hold the intermediate value without truncation.
</method>

<do_not_report>
- Precision loss that is documented as intentional rounding behavior
- Overflow conditions that are unreachable given the contract's input bounds (must prove reachability)
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the specific input or boundary that triggers the issue, (3) the wrong output or revert behavior produced, (4) the correct expected behavior, (5) concrete numerical example.
Report at most 5 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

PROMPT_DEX_INTEGRATION = """
<role>
You are a smart contract security analyst focused on AMM/DEX correctness: invariant preservation, external protocol compatibility, and liquidity accounting.
</role>

<scope>
Analyse ONLY the provided file.
This prompt targets files that implement AMM swap logic, liquidity management, or interact with external DEX protocols (Uniswap V2/V3, Curve, Velodrome/Aerodrome, Balancer, or stableswap derivatives).
</scope>

<method>
CHECK 1 — AMM INVARIANT PRESERVATION:
For each swap or trade function, verify the pool's core invariant (constant-product for CPMM, the stableswap invariant, etc.) still holds after the operation. Pay attention to operations that route through multiple pools or split a trade — each sub-operation must preserve the invariant independently — and to the order in which fees are applied relative to the invariant check.

CHECK 2 — DECIMAL NORMALIZATION:
When a pool handles tokens with different decimal counts, verify all amounts are normalized to a common precision before any invariant or pricing calculation and de-normalized afterward. Operating on raw amounts of differently-scaled tokens produces a wrong result.

CHECK 3 — POOL INITIALIZATION AND EDGE CASES:
For pool creation and initial liquidity addition, verify the protocol handles the zero-liquidity case (which otherwise causes division-by-zero on the first operation) and rejects or correctly handles tokens with non-standard decimals at initialization time.

CHECK 4 — EXTERNAL DEX PROTOCOL COMPATIBILITY:
When the contract calls into an external DEX, verify the call interface matches the actual deployed protocol version (forks may differ in signatures or fee structure), that multi-step pool interactions retrieve tokens correctly rather than leaving them credited inside the pool, and that any assumption about token slot ordering (token0/token1) is resolved by querying the pool at runtime rather than hardcoded — a hardcoded ordering assumption reverses direction or fee selection when addresses sort the opposite way. For factory calls that create a pool/pair, verify the case where the resource already exists is handled, since a revert-on-exists factory can be blocked by pre-creation.

CHECK 5 — LIQUIDITY CALCULATION FORMULA:
For any function that computes a liquidity delta, verify the formula matches what the underlying pool expects, including the correct single-sided formula for the current price's position relative to the range.

CHECK 6 — MULTI-STEP FILL AND REFUND ACCOUNTING:
In functions routing through multiple pools sequentially, when a step fills less than requested, verify what is debited from the caller and what is refunded reconcile against what was actually consumed. Refunding a difference that was never debited lets the caller pay nothing or receive free tokens. Enumerate every path where partial fills are possible and confirm debit and refund are mutually consistent.
</method>

<do_not_report>
- Rounding errors of 1 wei that cannot be accumulated
- Slippage without a concrete manipulation path
- Price impact without showing the specific profit path
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) which invariant or formula is violated, (3) concrete exploit scenario with numbers, (4) economic impact.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
Return ONLY raw JSON: {"vulnerabilities": {format_instructions}
</output>
"""

TOOL_LIST = {
    "SYSTEM_A1": SYSTEM_A1,
    "SYSTEM_A2": SYSTEM_A2,
    "SYSTEM_A3": SYSTEM_A3,
    "SYSTEM_A4": SYSTEM_A4,
    "SYSTEM_B": SYSTEM_B,
    "SYSTEM_C": SYSTEM_C,
    "SYSTEM_D": SYSTEM_D,
    "SYSTEM_E": SYSTEM_E,
    "SYSTEM_SV": SYSTEM_SV,
    "PROMPT_CONSERVATION": PROMPT_CONSERVATION,
    "PROMPT_AUTHORITY": PROMPT_AUTHORITY,
    "PROMPT_LIFECYCLE": PROMPT_LIFECYCLE,
    "PROMPT_SYMMETRY": PROMPT_SYMMETRY,
    "PROMPT_VALUE_DEPENDENCY": PROMPT_VALUE_DEPENDENCY,
    "PROMPT_FEE_ACCRUAL": PROMPT_FEE_ACCRUAL,
    "PROMPT_AUTHORIZED_SOURCE": PROMPT_AUTHORIZED_SOURCE,
    "SYSTEM_ORDER": SYSTEM_ORDER,
    "PROMPT_EXTERNAL_CALL_LIFECYCLE": PROMPT_EXTERNAL_CALL_LIFECYCLE,
    "PROBE_HELPER_CALLER": PROBE_HELPER_CALLER,
    "PROMPT_UPGRADEABLE": PROMPT_UPGRADEABLE,
    "PROMPT_REWARD_PRECISION": PROMPT_REWARD_PRECISION,
    "PROMPT_RANDOMNESS": PROMPT_RANDOMNESS,
    "PROMPT_ARITHMETIC": PROMPT_ARITHMETIC,
    "PROMPT_DEX_INTEGRATION": PROMPT_DEX_INTEGRATION,
}

# ---------------------------------------------------------------------------
# Scoring tables — rule_score() uses these to rank findings.
# FP patterns penalise known false-positive types; TP patterns reward
# concrete, exploit-ready findings. Keep sorted by impact.
# ---------------------------------------------------------------------------
FP_TYPE_PATTERNS = [("resource exhaustion", -2.0),("token ordering / direction", -1.5),("cross-language evm", -1.0),]
MILD_FP_TYPE_PATTERNS = [("missing access control", -0.8),]
TP_TYPE_PATTERNS = [("reentrancy", 1.5),("access control", 2.0),("missing state update", 2.5),("state corruption", 2.0),("accounting error", 2.5),("missing slippage", 2.5),("fund mixing", 2.0),("unvalidated external", 2.0),("gas griefing", 2.0),("silent failure", 2.0),("front-running", 2.0),("signature replay", 2.0),("denial of service", 1.5),("unit mismatch", 2.0),("type confusion", 2.0),("downcast", 1.5),("approval reset", 2.0),("fee evasion", 2.0),("delegated payout", 2.0),("integration mismatch", 2.0),("input validation", 1.5),("refund mismatch", 2.0),("missing modifier", 2.0),("manipulable return", 2.0),("initialization default", 1.5),("missing precondition", 2.0),("stale cache", 1.5),("max approval", 1.5),]
FP_TITLE_KEYWORDS = [("centralization risk", -3.0),("admin can", -2.0),("owner can", -2.0),("onlyowner", -2.0),("onlyrole", -2.0),("privileged function", -2.0),("governance attack", -2.0),("timelock bypass", -2.0),("pauseregistry", -4.0),("pauser role", -3.0),("theoretical", -3.0),("hypothetical", -3.0),("could potentially", -2.0),("might allow", -1.5),("may result in", -1.0),("if the value exceeds", -1.5),("potential overflow", -1.5),("could overflow", -1.5),("could truncate", -1.5),("generic reentrancy", -2.0),("standard reentrancy", -2.0),("well-known pattern", -1.5),("common vulnerability", -1.0),("best practice", -1.0),]
TP_TITLE_KEYWORDS = [("drain", 3.0),("steal", 3.0),("theft", 3.0),("fund loss", 3.0),("loss of funds", 3.0),("extract value", 2.5),("permissionless", 2.0),("callable by anyone", 2.0),("front-run", 2.0),("double count", 2.0),("missing update", 2.0),("state not updated", 2.0),("silent failure", 1.5),("wrong variable", 2.0),("missing reentrancy guard", 2.0),("permanently lost", 2.0),("locked in contract", 2.0),("not zeroed", 2.0),("not decremented", 2.0),("not reset", 2.0),("wrong recipient", 2.0),("id collision", 2.0),("anyone can call", 2.0),("avoid paying", 2.0),("unvalidated", 2.0),("not validated", 1.5),("stale rate", 1.5),("stale snapshot", 1.5),("unconsumed approval", 2.0),("leftover spender", 2.0),("stuck native", 2.0),("missing receive", 2.0),("fee skipped", 2.0),("fee bypass", 2.0),("delegated payout", 2.0),("integration mismatch", 1.5),("downstream consumer", 1.5),("from any address", 2.0),("arbitrary from", 2.0),("refund mismatch", 2.0),("refund without receipt", 2.0),("missing modifier", 2.0),("public state mutation", 1.5),("manipulable return", 2.0),("trusts external view", 1.5),("initialization default", 1.5),("init grants", 1.5),("no slippage", 2.0),("no slippage protection", 2.0),("missing precondition", 2.0),("stale cache", 1.5),("uncleared cache", 1.5),("max approval", 1.5),("unbounded allowance", 1.5),("flash-loan spike", 1.5),("price spike", 1.5),("init grants max", 1.5),("stale pointer", 1.5),("uninitialized loop", 1.5),("unvalidated token", 1.5),("address(0) transfer", 1.5),("zero target", 1.5),("partial-fill remainder", 1.5),("msg.value reuse", 2.5),("hook reentrancy", 2.0),("erc777", 2.0),("erc1155 callback", 2.0),("erc721 callback", 2.0),("accumulator overflow", 2.0),("reward monopoli", 2.0),("pending reset", 2.0),("aggregator refund", 2.0),("bidirectional slippage", 2.0),("weak randomness", 2.5),("timestamp manipulation", 2.0),("miner can manipulate", 2.0),("block.timestamp", 2.0),("onboarding self-register", 2.0),("self-register", 2.0),("deployed counter", 2.0),("outstanding counter", 2.0),("allocated counter", 2.0),("memory vs storage", 2.0),("storage reference", 1.5),]

# ---------------------------------------------------------------------------
# Scope / file-filtering helpers
# ---------------------------------------------------------------------------
_SOURCE_EXT_RE = re.compile(r'\.(sol|vy|cairo|move|rs|yul)$', re.IGNORECASE)

def _classify_scope_entry(entry: str, paths: set, dir_prefixes: set, glob_patterns: list) -> None:
    """Route one scope.txt / out_of_scope.txt line to exact-path, dir-prefix, or glob bucket."""

    entry = entry.strip().strip('"\'')
    if entry.startswith('./'):
        entry = entry[2:]
    
    entry = entry.lstrip('/')
    if not entry or len(entry) < 2:
        return
    
    if '*' in entry or '?' in entry:
        glob_patterns.append(entry)
        return
    
    if _SOURCE_EXT_RE.search(Path(entry).name):
        paths.add(entry)
        paths.add(entry.lower())
    else:
        dir_prefixes.add(entry.lower().rstrip('/'))

_SCOPE_HEADING_RE = re.compile(r'^#{1,4}\s+(?:audit\s+)?(?:in[\s\-]*)?scope\b', re.IGNORECASE)
_NEXT_HEADING_RE = re.compile(r'^#{1,4}\s+\w')

def _parse_readme_scope(text: str, paths: set, prefixes: set, globs: list) -> None:
    """Extract in-scope file paths from a README Audit Scope / Scope section.
    Only called when scope.txt is absent. Extracts lines that contain a recognised
    source extension AND a path separator — i.e., real file paths, not prose."""

    in_scope = False
    in_fenced = False
    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith('```') or stripped.startswith('~~~'):
            in_fenced = not in_fenced
            continue

        if in_fenced:
            continue

        if _SCOPE_HEADING_RE.match(stripped):
            in_scope = True
            continue

        if _NEXT_HEADING_RE.match(stripped) and in_scope:
            break

        if not in_scope:
            continue

        for m in re.finditer(r'\b([\w./\-]+\.(?:sol|vy|cairo|move|rs|yul))\b', line, re.IGNORECASE):
            candidate = m.group(1)

            if '/' in candidate:
                _classify_scope_entry(candidate, paths, prefixes, globs)

def _collect_scope(source_dir: Path) -> tuple[set, set, list, set, set, list]:
    """
    Priority order:
    1. scope.txt — explicit allowlist (17/19 C4 projects). Supersedes everything else.
    2. README Audit Scope / Scope section — targeted path extraction for Sherlock/Cantina
       repos that list file paths under a scope heading (3 of 10 Sherlock repos).
       Only fires when scope.txt is absent AND README yields ≥1 path with '/'.
    3. out_of_scope.txt — blocklist fallback (only when neither 1 nor 2 applies).
    Returns (ins_paths, ins_prefixes, ins_globs, oos_paths, oos_prefixes, oos_globs).
    """

    def _read_scope_file(path: Path) -> tuple[set, set, list]:
        p: set = set()
        pre: set = set()
        g: list = []

        try:

            for raw in path.read_text(encoding='utf-8', errors='ignore').splitlines():
                entry = raw.strip()

                if not entry or entry.startswith('#'):
                    continue
                _classify_scope_entry(entry, p, pre, g)
        except Exception:
            pass

        return p, pre, g

    scope_txt = source_dir / 'scope.txt'
    if scope_txt.is_file():
        ins_p, ins_pre, ins_g = _read_scope_file(scope_txt)

        if ins_p or ins_pre or ins_g:
            return ins_p, ins_pre, ins_g, set(), set(), []

    for readme_name in ('README.md', 'Readme.md', 'readme.md'):
        readme_path = source_dir / readme_name

        if readme_path.is_file():
            try:
                ins_p: set = set()
                ins_pre: set = set()
                ins_g: list = []
                _parse_readme_scope(
                    readme_path.read_text(encoding='utf-8', errors='ignore'),
                    ins_p, ins_pre, ins_g,
                )

                if ins_p or ins_pre or ins_g:
                    # Validate: at least one path must exist under source_dir.
                    # Guards against README formats where paths are relative to a
                    # subdirectory (e.g. initia-move: "sources/foo.move" listed under
                    # a GitHub URL context of "vip-module/"). Those paths don't exist
                    # at the repo root, so we fall through to directory heuristics.

                    if any((source_dir / p).is_file() for p in list(ins_p)[:30]):
                        return ins_p, ins_pre, ins_g, set(), set(), []
            except Exception:
                pass
            break

    oos_p, oos_pre, oos_g = set(), set(), []
    oos_txt = source_dir / 'out_of_scope.txt'
    if oos_txt.is_file():
        oos_p, oos_pre, oos_g = _read_scope_file(oos_txt)

    return set(), set(), [], oos_p, oos_pre, oos_g

def _normalize_text(text: str) -> str:
    return re.sub(r'\s+', ' ', text.lower().strip())

def _token_set(text: str) -> set:
    words = re.findall(r'[a-z][a-z0-9_]+', _normalize_text(text))
    stop = {'the', 'and', 'for', 'that', 'this', 'with', 'from', 'are', 'was', 'can', 'may','could', 'would', 'should', 'not', 'but', 'has', 'have', 'had', 'will', 'its','when', 'which', 'where', 'been', 'being', 'does', 'into', 'also', 'than', 'then'}
    return {w for w in words if len(w) > 2 and w not in stop}

def _jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0

    if not set_a or not set_b:
        return 0.0

    return len(set_a & set_b) / len(set_a | set_b)

def _findings_similar(a, b) -> bool:
    """True when token overlap across title and description meets same-root-cause threshold."""

    same_file = (a.file == b.file)
    title_sim = _jaccard_similarity(_token_set(a.title), _token_set(b.title))
    desc_sim = _jaccard_similarity(_token_set(a.description), _token_set(b.description))
    type_a = _normalize_text(a.vulnerability_type)
    type_b = _normalize_text(b.vulnerability_type)
    type_similar = (type_a == type_b) or (type_a in type_b) or (type_b in type_a)
    if same_file:
        if title_sim >= 0.25:
            return True

        if desc_sim >= 0.20 and type_similar:
            return True
    else:
        if title_sim >= 0.50 and type_similar:
            return True

    return False

def _merge_group(group: list) -> "Vulnerability":
    """Collapse a cluster into one finding using the highest-confidence member as the base template."""

    if len(group) == 1:
        return group[0]

    group.sort(key=lambda v: (-v.confidence, -len(v.description)))
    best = group[0]
    best_title = max(group, key=lambda v: (v.confidence, len(v.title))).title
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best_severity = max(group, key=lambda v: sev_order.get(v.severity.value if v.severity else "low", 0)).severity
    best_confidence = max(v.confidence for v in group)
    vtypes = []
    seen_vt = set()

    for v in group:
        vt_norm = _normalize_text(v.vulnerability_type)

        if vt_norm not in seen_vt:
            vtypes.append(v.vulnerability_type)
            seen_vt.add(vt_norm)

    combined_vtype = vtypes[0] if len(vtypes) == 1 else " / ".join(vtypes[:2])
    locations = []
    seen_loc = set()
    for v in group:
        loc_norm = _normalize_text(v.location)

        if loc_norm not in seen_loc:
            locations.append(v.location)
            seen_loc.add(loc_norm)

    combined_location = "; ".join(locations[:3])
    all_sentences = []
    seen_sentences = set()
    for v in group:
        sentences = re.split(r'(?<=[.!?])\s+', v.description.strip())

        for s in sentences:
            s = s.strip()

            if not s:
                continue

            s_norm = _normalize_text(s)
            s_tokens = _token_set(s)
            is_dup = False

            for existing_norm in seen_sentences:
                existing_tokens = _token_set(existing_norm)

                if _jaccard_similarity(s_tokens, existing_tokens) > 0.6:
                    is_dup = True
                    break

            if not is_dup:
                all_sentences.append(s)
                seen_sentences.add(s_norm)

    combined_desc = ""
    for s in all_sentences:
        candidate = combined_desc + (" " if combined_desc else "") + s

        if len(candidate) <= 800:
            combined_desc = candidate
        else:
            remaining = 800 - len(combined_desc) - 1

            if remaining > 40:
                combined_desc = combined_desc + " " + s[:remaining-3] + "..."
            break

    if not combined_desc:
        combined_desc = best.description[:800]

    merged = Vulnerability(
        title=best_title,
        description=combined_desc,
        vulnerability_type=combined_vtype,
        severity=best_severity,
        confidence=best_confidence,
        location=combined_location,
        file=best.file,
        reported_by_model=best.reported_by_model,
        root_cause=best.root_cause,
        fix_location=best.fix_location,
        violated_invariant=best.violated_invariant,
    )
    return merged

# ---------------------------------------------------------------------------
# Heuristic + LLM deduplication pipeline
# ---------------------------------------------------------------------------
def cluster_findings(vulns: list) -> list:
    """Group findings using `_findings_similar`. No size cap, no early-return.
    Every input lands in exactly one cluster. Returns list[list[Vulnerability]]."""

    n = len(vulns)
    assigned = [False] * n
    clusters = []
    for i in range(n):
        if assigned[i]:
            continue

        cluster = [vulns[i]]
        assigned[i] = True

        for j in range(i + 1, n):
            if assigned[j]:
                continue

            for member in cluster:
                if _findings_similar(member, vulns[j]):
                    cluster.append(vulns[j])
                    assigned[j] = True
                    break

        clusters.append(cluster)

    return clusters

def _merge_clusters_across_chunks(clusters: list) -> list:
    """Glue clusters from different chunks that describe the same bug.
    Uses union-find with `_findings_similar` edges between cluster representatives."""

    n = len(clusters)
    if n <= 1:
        return clusters

    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]

        return x

    def union(a, b):
        ra, rb = find(a), find(b)

        if ra != rb:
            parent[ra] = rb

    reps = [max(c, key=lambda v: v.confidence) for c in clusters]
    for i in range(n):
        for j in range(i + 1, n):
            if _findings_similar(reps[i], reps[j]):
                union(i, j)

    groups = defaultdict(list)
    for i, c in enumerate(clusters):
        groups[find(i)].extend(c)

    return list(groups.values())

# ---------------------------------------------------------------------------
# Final output selection — severity-aware round-robin across clusters
# ---------------------------------------------------------------------------
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def roundrobin_select(vulns, max_output=100):
    """Select up to max_output findings with diversity across clusters.
    Sorting is severity-first so criticals always precede highs in the output.
    Round-robins across clusters to avoid any single file/type dominating.
    Default cap is 100 — matches the analyze_project output limit."""

    if len(vulns) <= max_output:
        return sorted(vulns, key=lambda v: (
            -_SEV_ORDER.get(v.severity.value if v.severity else "low", 0),
            -rule_score(v), -len(v.description), v.title,
        ))

    clusters = cluster_findings(vulns)
    sorted_clusters = [
        sorted(c, key=lambda v: (-_SEV_ORDER.get(v.severity.value if v.severity else "low", 0), -rule_score(v)))
        for c in clusters
    ]
    sorted_clusters.sort(key=lambda c: (
        -_SEV_ORDER.get(c[0].severity.value if c[0].severity else "low", 0),
        -rule_score(c[0]),
    ))
    selected = []
    while len(selected) < max_output:
        progress = False

        for cluster in sorted_clusters:
            if cluster:
                selected.append(cluster.pop(0))
                progress = True

                if len(selected) >= max_output:
                    break

        if not progress:
            break

    return selected

def rule_score(vuln) -> float:
    """Heuristic score used to rank findings before the 100-finding output cap; higher = reported first."""

    score = 5.0
    vuln_type = safe_lower(vuln.vulnerability_type)
    title = safe_lower(vuln.title)
    desc = safe_lower(vuln.description)
    severity = vuln.severity.value if vuln.severity else ""
    confidence = clamp(vuln.confidence if vuln.confidence else 0.5, 0.0, 1.0)
    text = f"{title} {desc}"
    tp_matched = False
    fp_matched = False

    for tp_type, boost in TP_TYPE_PATTERNS:
        if tp_type in vuln_type:
            score += boost
            tp_matched = True
            break

    if not tp_matched:
        for fp_type, penalty in FP_TYPE_PATTERNS:
            if fp_type in vuln_type:
                score += penalty
                fp_matched = True
                break

    if not tp_matched and not fp_matched:
        for mild_type, penalty in MILD_FP_TYPE_PATTERNS:
            if mild_type in vuln_type:
                score += penalty
                break

    if severity == "critical":
        score += 2.0
    if severity == "high":
        score += 0.5
    elif severity == "medium":
        score -= 2.0
    elif severity == "low":
        score -= 4.0
    if confidence >= 0.95:
        score += 0.3
    elif confidence < 0.80:
        score -= 1.0

    fp_keyword_total = 0.0
    for keyword, weight in FP_TITLE_KEYWORDS:
        if keyword in text:
            fp_keyword_total += weight

    fp_keyword_total = max(fp_keyword_total, -4.0)
    score += fp_keyword_total
    tp_keyword_total = 0.0
    for keyword, weight in TP_TITLE_KEYWORDS:
        if keyword in text:
            tp_keyword_total += weight

    score += min(tp_keyword_total, 6.0)
    wc = word_count(desc)
    if wc < 15:
        score -= 2.0
    elif wc > 80:
        score += 0.5

    if re.search(r'\b(function|fn)\s+\w+\(', text):
        score += 0.3

    if re.search(r'line\s+\d+', text):
        score += 0.2

    if re.search(r'step\s+\d', text) or 'exploit scenario' in text:
        score += 0.5

    return score

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Vulnerability(BaseModel):
    title: str
    description: str
    vulnerability_type: str
    severity: Severity
    confidence: float
    location: str
    file: str
    id: str | None = None
    reported_by_model: str = ""
    status: str = "proposed"
    root_cause: str | None = None
    fix_location: str | None = None
    violated_invariant: str | None = None

    def __init__(self, **data):
        super().__init__(**data)

        if not self.id:
            id_source = f"{self.file}:{self.title}"
            self.id = hashlib.md5(id_source.encode()).hexdigest()[:16]

class Vulnerabilities(BaseModel):
    vulnerabilities: list[Vulnerability]

class AnalysisResult(BaseModel):
    project: str
    timestamp: str
    files_analyzed: int
    files_skipped: int
    total_vulnerabilities: int
    vulnerabilities: list[Vulnerability]
    token_usage: dict[str, int]

# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------
class BaselineRunner:
    def __init__(self, config: dict[str, Any] | None = None, inference_api: str = None):
        """Configure runner with model name and proxy endpoint; defaults to PRIMARY_MODEL and env INFERENCE_API."""

        self.config = config or {}
        self.model = self.config.get('model', PRIMARY_MODEL)
        self.inference_api = inference_api or os.getenv('INFERENCE_API', "http://bitsec_proxy:8000")
        self.project_id = os.getenv('PROJECT_ID', "local")
        self.job_id = os.getenv('JOB_ID', "local")
        self.inference_api_key = os.getenv('INFERENCE_API_KEY')

        if not self.inference_api_key:
            raise ValueError("An inference API key is required.")

        print(f"[INFO] Runner init | model={self.model} | api={self.inference_api} | key_set={bool(self.inference_api_key)}")

    def inference(self, messages: dict[str, Any], model: str = None, timeout:int = 650, temperature: float = 0.01, call_type: str = "analyze", file: str = "-", tools: list = None, tool_choice=None, thinking_budget: int = 0) -> dict[str, Any]:
        """POST to the bitsec proxy; PRIMARY_MODEL returns `content` at top level, not inside `choices`."""

        used_model = model or self.config.get('model', PRIMARY_MODEL)

        # Average observed throughput per model — used to compute max_tokens budget.
        # Higher = larger cap = fewer truncations; floor of 2048 guards degenerate short timeouts.
        _TOK_RATE_FLOOR = {
            PRIMARY_MODEL:   85,
            THINKING_MODEL:  55,
            JSON_MODEL:      80,
        }
        _rate = _TOK_RATE_FLOOR.get(used_model, 55)
        # _budget_tokens: output budget for the HARD LIMIT note (subtracts thinking_budget
        # because the note covers combined thinking+output and thinking is separate).
        # _max_tokens: API cap for output tokens only — must NOT subtract thinking_budget
        # since the API max_tokens parameter counts output tokens only, not thinking tokens.
        _budget_tokens = min(65536, max(2048, int(timeout * _rate) - thinking_budget))
        _max_tokens    = min(65536, max(2048, int(timeout * _rate)))

        # Inject total token budget into the system message so the model's own reasoning
        # process respects the limit.  Some providers (e.g. AtlasCloud) generate thinking
        # tokens outside the max_tokens cap, making the API parameter alone ineffective.
        # An explicit instruction in the system prompt causes the model to self-regulate
        # its thinking chain, preventing 80K+ token overflows regardless of provider.
        # Skip for tool-use (agentic) calls: the budget constraint causes the model to
        # output near-nothing (2-25 tokens) on its first turn to "conserve budget",
        # which defeats the entire purpose of the agentic deep-dive.
        messages = list(messages)  # shallow copy — do not mutate the caller's list
        if tools is None:
            _total_budget = _budget_tokens + thinking_budget  # thinking + output combined
            _budget_note = (
                f"HARD LIMIT: Your total generation budget (reasoning/thinking tokens + output tokens combined) "
                f"is {_total_budget} tokens (budget for this {timeout}s call). "
                f"Produce a complete and useful response within this budget."
            )
            if messages and messages[0].get("role") == "system":
                messages[0] = {**messages[0], "content": messages[0]["content"] + f"\n\n{_budget_note}"}
            else:
                messages.insert(0, {"role": "system", "content": _budget_note})

        payload = {
            "model": used_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": _max_tokens,
            "thinking": {"type": "enabled", "budget_tokens": thinking_budget} if thinking_budget > 0 else {"type": "disabled"},
        }

        if used_model in _PROVIDER_ROUTING:
            payload["provider"] = _PROVIDER_ROUTING[used_model]

        if tools is not None:
            payload["tools"] = tools
            # Prevent proxy from injecting response_format={"type":"json_object"} into tool-use
            # calls — JSON object mode is structurally incompatible with tool_call responses.
            # The proxy only injects if response_format is not already a dict, so an explicit
            # "text" value blocks it without affecting OpenRouter's tool-call routing.
            payload["response_format"] = {"type": "text"}

        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

        headers = {
            "x-inference-api-key": self.inference_api_key,
            "x-project-id": self.project_id or "local",
            "x-job-id": self.job_id,
            "x-call-type": call_type,
            "x-file": file,
        }

        inference_url = f"{self.inference_api}/inference"

        # Hard ceiling: never exceed the total pipeline deadline regardless of phase.
        # Per-phase tightening is the caller's responsibility (scan calls pass a
        # deadline-aware timeout from _submit_analyze; verifier/merge pass their
        # own budget). Using scan_deadline here would silently starve later phases
        # (verifier, merge) when they start before scan_deadline has elapsed.
        total_dl = getattr(self, '_total_deadline', None)
        if total_dl and time.time() < total_dl:
            timeout = min(timeout, max(5, int(total_dl - time.time())))
        elif total_dl:
            timeout = 5  # past total deadline — expire immediately

        print(f"[DEBUG] Inference -> model={used_model} call={call_type} file={file} timeout={timeout}s")
        
        now = time.time()

        try:
            resp = requests.post(
                inference_url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            elapsed = time.time() - now
            print(f"[DEBUG] Inference OK  call={call_type} file={file} elapsed={elapsed:.1f}s in={result.get('input_tokens',0)} out={result.get('output_tokens',0)}")

            return result
        except Exception as exc:
            elapsed = time.time() - now
            print(f"[ERROR] Inference FAIL call={call_type} file={file} elapsed={elapsed:.1f}s | {type(exc).__name__}: {exc}")

            raise

    def clean_json_response(self, response_content: str) -> dict[str, Any]:
        """Strip markdown fences and leading noise, then extract the first JSON object; returns {} on failure."""

        while response_content.startswith("_\n"):
            response_content = response_content[2:]
        response_content = response_content.strip()

        if response_content.startswith("return"):
            response_content = response_content[6:]
        response_content = response_content.strip()

        if response_content.startswith("```"):
            lines = response_content.splitlines()

            if lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            response_content = "\n".join(lines).strip()

        try:
            return json.loads(response_content)
        except json.JSONDecodeError:
            pass

        start = response_content.find('{')
        if start != -1:
            depth = 0
            end = -1
            in_string = False
            escape_next = False

            for i in range(start, len(response_content)):
                c = response_content[i]

                if escape_next:
                    escape_next = False
                    continue

                if c == '\\' and in_string:
                    escape_next = True
                    continue

                if c == '"' and not escape_next:
                    in_string = not in_string
                    continue

                if in_string:
                    continue

                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1

                    if depth == 0:
                        end = i
                        break

            if end != -1:
                json_str = response_content[start:end + 1]

                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass

                fixed = re.sub(r',\s*([}\]])', r'\1', json_str)

                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass

            json_str = response_content[start:]
            last_complete = -1
            depth = 0
            in_str = False
            esc2 = False

            for i in range(len(json_str)):
                c = json_str[i]

                if esc2:
                    esc2 = False
                    continue

                if c == '\\' and in_str:
                    esc2 = True
                    continue

                if c == '"':
                    in_str = not in_str
                    continue

                if in_str:
                    continue

                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1

                    if depth == 1:  # closed a vulnerability object (depth back to array level)
                        last_complete = i

            if last_complete > 0:
                truncated = json_str[:last_complete + 1] + ']}'
                truncated = re.sub(r',\s*([}\]])', r'\1', truncated)

                try:
                    return json.loads(truncated)
                except json.JSONDecodeError:
                    pass

            json_str = re.sub(r',\s*([}\]])', r'\1', json_str)
            quote_count = 0
            esc3 = False

            for c in json_str:
                if esc3:
                    esc3 = False
                    continue

                if c == '\\':
                    esc3 = True
                    continue

                if c == '"':
                    quote_count += 1

            if quote_count % 2 != 0:
                json_str += '"'
            json_str += ']}'

            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

        preview = response_content[:500].replace('\n', '\\n')
        print(f"  WARNING: Could not parse JSON. Preview: {preview}")

        return {}

    def _tool_list_files(self, source_dir: Path, directory: str) -> str:
        """Sandbox tool: list files in directory relative to source_dir; path-traversal blocked by resolve() check."""

        root = source_dir.resolve()
        target = (source_dir / directory.replace(" ", "")).resolve()

        if not str(target).startswith(str(root)):
            return json.dumps({"error": "Access denied: path outside project"})

        if not target.is_dir():
            return json.dumps({"error": f"Not a directory: {directory}"})

        files = []
        for item in sorted(target.iterdir()):
            rel = str(item.resolve().relative_to(root))
            files.append(rel + ("/" if item.is_dir() else ""))

        return json.dumps({"files": files})

    def _tool_read_file(self, source_dir: Path, file_path: str) -> str:
        """Sandbox tool: read a file relative to source_dir; path-traversal blocked and content capped at 50k chars."""

        root = source_dir.resolve()
        target = (source_dir / file_path.replace(" ", "")).resolve()

        if not str(target).startswith(str(root)):
            return json.dumps({"error": "Access denied: path outside project"})

        if not target.is_file():
            return json.dumps({"error": f"Not a file: {file_path}"})

        try:
            return target.read_text(encoding="utf-8")[:50_000]
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _execute_tool_call(self, tool_call: dict, source_dir: Path) -> str:
        """Dispatch a single tool call by name; unrecognised tools return an error string instead of raising."""

        try:
            fn = tool_call.get("function", {})
            name = fn.get("name")
            args = json.loads(fn.get("arguments", "{}"))
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid tool arguments JSON: {exc}"})

        if name == "list_files":
            return self._tool_list_files(source_dir, args.get("directory", "."))
        elif name == "read_file":
            return self._tool_read_file(source_dir, args.get("file_path", ""))
        elif name == "report_vulnerabilities":
            return json.dumps(args)

        return json.dumps({"error": f"Unknown tool: {name}"})

    def _seed_file_context(self, messages: list, source_dir: Path, relative_path: str, tool_call_id: str) -> list:
        """Prime the agentic conversation with the target file's content before the first LLM turn."""

        list_id = f"{tool_call_id}-list"
        messages.append({"role": "assistant", "tool_calls": [{"id": list_id, "type": "function", "function": {"name": "list_files", "arguments": json.dumps({"directory": "."})}}]})
        messages.append({"role": "tool", "tool_call_id": list_id, "content": self._tool_list_files(source_dir, ".")})
        messages.append({"role": "assistant", "tool_calls": [{"id": tool_call_id, "type": "function", "function": {"name": "read_file", "arguments": json.dumps({"file_path": relative_path})}}]})
        messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": self._tool_read_file(source_dir, relative_path)})

        return messages

    def _run_agentic_pass(self, source_dir: Path, relative_path: str, deadline: float, seed_id: str,
                           lang_hint: str = "", protocol_context: str = "") -> tuple[list, int, int]:
        """Run one agentic tool-use session for a single target file. Returns (vulns, in_tok, out_tok)."""

        if time.monotonic() >= deadline:
            return [], 0, 0

        _hint_block = f"\n{lang_hint}" if lang_hint else ""
        _proto_block = f"\n{protocol_context}" if protocol_context else ""

        # Prefer ROUTER_MODEL (235b-instruct) for stronger cross-file reasoning.
        # Falls back to THINKING_MODEL on 502/503 (proxy unavailability).
        messages = [
            {"role": "system", "content": AGENTIC_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"Perform a deep-dive security audit on: {relative_path}\n"
                f"{_hint_block}{_proto_block}"
                "The file has been pre-loaded via the tool result below. "
                "Use at most 2 additional read_file calls for related files, then call report_vulnerabilities."
            )},
        ]
        messages = self._seed_file_context(messages, source_dir, relative_path, seed_id)
        all_vulns: list[Vulnerability] = []
        total_in = total_out = 0
        reported = False
        forced = False
        extra_reads = 0          # read_file calls beyond the seeded primary file
        MAX_EXTRA_READS = 2
        _ag_model = ROUTER_MODEL

        for turn in range(6):
            if (time.monotonic() >= deadline or turn >= 4) and not reported:
                if forced:
                    break

                messages.append({"role": "user", "content": "Time is up. Call report_vulnerabilities NOW with all findings so far."})
                tool_choice = {"type": "function", "function": {"name": "report_vulnerabilities"}}
                forced = True
            else:
                tool_choice = "auto"

            try:
                _ag_timeout = min(650, max(5, int(deadline - time.monotonic())))
                response = self.inference(messages=messages, model=_ag_model, timeout=_ag_timeout, call_type="agentic", file=relative_path, tools=TOOL_DEFINITIONS, tool_choice=tool_choice)
            except requests.exceptions.HTTPError as exc:
                _status = exc.response.status_code if exc.response is not None else 0
                if _status in (502, 503) and _ag_model == ROUTER_MODEL:
                    print(f"[agentic] ROUTER_MODEL {_status} → falling back to THINKING_MODEL for {relative_path}")
                    _ag_model = THINKING_MODEL
                    try:
                        _ag_timeout = min(650, max(5, int(deadline - time.monotonic())))
                        response = self.inference(messages=messages, model=_ag_model, timeout=_ag_timeout, call_type="agentic", file=relative_path, tools=TOOL_DEFINITIONS, tool_choice=tool_choice)
                    except Exception:
                        break
                else:
                    break
            except Exception:
                break

            # Proxy returns input_tokens/output_tokens at the top level (not nested under usage).
            # Fall back to the OpenAI-style usage dict for any model that wraps them there.
            total_in  += response.get("input_tokens",  0) or response.get("usage", {}).get("prompt_tokens",     0)
            total_out += response.get("output_tokens", 0) or response.get("usage", {}).get("completion_tokens", 0)
            msg = response.get("choices", [{}])[0].get("message", {})
            tool_calls = msg.get("tool_calls")

            if not tool_calls:
                content = msg.get("content", "")
                if content and not reported and not forced:
                    # Model returned text analysis instead of a tool call.
                    # Push it onto history and force a report_vulnerabilities call.
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": "You provided analysis as text instead of calling a tool. Call report_vulnerabilities NOW with those findings."})
                    tool_choice = {"type": "function", "function": {"name": "report_vulnerabilities"}}
                    forced = True
                    continue
                break

            messages.append(msg)

            for tc in tool_calls:
                fn_name = tc.get("function", {}).get("name")

                if fn_name == "read_file" and extra_reads >= MAX_EXTRA_READS:
                    result_str = json.dumps({"error": f"read_file quota exhausted (max {MAX_EXTRA_READS} additional reads). Call report_vulnerabilities now."})
                else:
                    if fn_name == "read_file":
                        extra_reads += 1
                    result_str = self._execute_tool_call(tc, source_dir)

                if fn_name == "report_vulnerabilities":
                    reported = True

                    try:
                        args = json.loads(tc["function"]["arguments"])

                        for vd in args.get("vulnerabilities", []):
                            vd["reported_by_model"] = f"{_ag_model}_agentic"
                            vd.setdefault("title", "Untitled"); vd.setdefault("description", vd["title"])
                            vd.setdefault("vulnerability_type", "Unknown"); vd.setdefault("severity", "medium")
                            vd.setdefault("confidence", 0.7); vd.setdefault("location", "Unknown")
                            vd.setdefault("file", relative_path)

                            try:
                                all_vulns.append(Vulnerability(**vd))
                            except Exception:
                                pass
                    except Exception:
                        pass

                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": result_str})

            if reported or forced:
                break

        print(f"[agentic] file={relative_path} model={_ag_model} vulns={len(all_vulns)} in={total_in} out={total_out}")

        return all_vulns, total_in, total_out

    def analyze_file(self, source_dir: Path, relative_path: str, related_files_list: list[str], model: str = None, system_prompt: str = None, prompt_name: str = None, context: str = None, sleep_timeout: int = 5, inference_timeout: int = 650, temperature: float = 0.01, thinking_budget: int = 0, protocol_context: str = None, rs_flavor: str = "")  -> tuple[Vulnerabilities, int, int]:
        """Run one (file, prompt) analysis in a thread-pool worker; returns (Vulnerabilities, input_tokens, output_tokens).

        rs_flavor: project-level Rust chain hint ("anchor"|"cosmwasm"|"generic"|"").
        Used as fallback when the file itself lacks chain-identifying markers (e.g. state.rs,
        helpers.rs inside a CosmWasm or Anchor project that don't import entry-point crates).
        """

        start_time = time.time()

        file_path = Path(relative_path)
        main_file_content = ""

        with open(source_dir / file_path, 'r', encoding='utf-8') as f:
            main_file_content = f.read()

        system_prompt = system_prompt.replace(
            "{format_instructions}",
            '[{"title": "...", "description": "...", "vulnerability_type": "...", '
            '"severity": "critical|high|medium|low", "confidence": 0.0-1.0, '
            '"location": "FunctionName", "file": "path/to/file.sol"}]}',
        )

        file_content_for_user_prompt = f"""
            Main File: {file_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {main_file_content}
            ```
        """

        # Cap each related file at 12 000 chars, total at 30 000 chars.
        _RF_FILE_CAP  = 12_000
        _RF_TOTAL_CAP = 30_000
        related_files_content_for_user_prompt = ""

        for related_file_path in related_files_list:
            if len(related_files_content_for_user_prompt) >= _RF_TOTAL_CAP:
                break

            try:
                rp = Path(related_file_path)
                related_file_path = rp if rp.is_absolute() else source_dir / rp

                with open(related_file_path, 'r', encoding='utf-8') as f:
                    related_files_content = f.read()

                if len(related_files_content) > _RF_FILE_CAP:
                    related_files_content = related_files_content[:_RF_FILE_CAP] + "\n... [truncated]"

                chunk = f"""
                    Related File: {related_file_path}
                    ```{related_file_path.suffix[1:] if related_file_path.suffix else 'txt'}
                    {related_files_content}
                    ```
                """
                remaining = _RF_TOTAL_CAP - len(related_files_content_for_user_prompt)
                related_files_content_for_user_prompt += chunk[:remaining]

            except Exception as e:
                continue
        lang_hint = ""

        if file_path.suffix == '.rs':
            _is_anchor = ('anchor_lang' in main_file_content or '#[program]' in main_file_content or 'declare_id!' in main_file_content)
            _is_cosmwasm = (not _is_anchor and ('use cosmwasm_std' in main_file_content or '#[entry_point]' in main_file_content or 'use cw_storage_plus' in main_file_content))

            if _is_anchor:
                lang_hint = ANCHOR_LANG_HINT
            elif _is_cosmwasm:
                lang_hint = GENERIC_LANG_HINT_BY_EXT[".rs_cosmwasm"]
            elif rs_flavor == "cosmwasm":
                # Project-level fallback: helper/state modules in a CosmWasm project that
                # don't import cosmwasm_std directly still belong to the CosmWasm frame.
                lang_hint = GENERIC_LANG_HINT_BY_EXT[".rs_cosmwasm"]
            elif rs_flavor == "anchor":
                lang_hint = ANCHOR_LANG_HINT
            else:
                lang_hint = GENERIC_LANG_HINT_BY_EXT[".rs_generic"]
        elif file_path.suffix == '.cairo':
            lang_hint = CAIRO_LANG_HINT
        else:
            lang_hint = GENERIC_LANG_HINT_BY_EXT.get(file_path.suffix, "")

        project_context = f"""
============================================================
PROJECT CONTEXT (README)
============================================================
{context}
""" if context else ""
        protocol_context_block = f"""
============================================================
PROTOCOL MODEL CONTEXT
============================================================
{protocol_context}
""" if protocol_context else ""
        user_prompt = dedent(f"""
            Analyze this {file_path.suffix} file for security vulnerabilities:
            {lang_hint}
            {project_context}
            {protocol_context_block}
            {file_content_for_user_prompt}
            {related_files_content_for_user_prompt}
            Identify and report security vulnerabilities found.
        """)

        # If the deferred-collection window has already closed, skip without making
        # any HTTP call.  This prevents dangling billed requests the agent will never
        # receive — the 5-second fallback timeout is not sufficient because the proxy
        # still queues the request upstream.
        _collection_dl = getattr(self, '_collection_deadline', None)
        if _collection_dl and time.time() >= _collection_dl:
            return Vulnerabilities(vulnerabilities=[]), 0, 0

        print(f"[INFO] analyze_file START file={relative_path} prompt={prompt_name}")
        max_retries = 2

        for attempt in range(max_retries):
            try:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ]

                # Recompute effective timeout at execution time, not submission time.
                # Futures can sit in the executor queue for many minutes; the timeout
                # frozen at _submit_analyze() may be far larger than what the scan
                # budget actually has left when this worker finally starts.
                # Cap to _collection_deadline (scan_deadline + 90s) so the timeout
                # matches the actual collection window including the deferred Phase 1/2 gap.
                _effective_timeout = inference_timeout

                if _collection_dl:
                    _collection_remaining = max(5, int(_collection_dl - time.time()))
                    _effective_timeout = min(inference_timeout, _collection_remaining)
                
                response = self.inference(messages=messages, model=model, timeout=_effective_timeout, temperature=temperature, call_type=f"analyze:{prompt_name}", file=relative_path, thinking_budget=thinking_budget)
                response_content = (response.get("content") or response.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                msg_json = self.clean_json_response(response_content)

                # Empty parse result means the model returned prose, truncated JSON,
                # or a completely empty body. Raise so the retry path fires rather than
                # silently recording zero findings.
                if not msg_json:
                    raise ValueError(f"Model returned unparseable content (len={len(response_content)})")

                # Non-empty JSON that lacks 'vulnerabilities' is a malformed response
                # (schema echo, wrong object type, etc.) — also worth retrying.
                if "vulnerabilities" not in msg_json:
                    raise ValueError(f"Model returned JSON without 'vulnerabilities'. Keys: {list(msg_json)[:5]}")

                if "vulnerabilities" in msg_json and isinstance(msg_json["vulnerabilities"], list):
                    sanitized = []

                    for v in msg_json["vulnerabilities"]:
                        if not isinstance(v, dict):
                            continue

                        if not v.get("title") and not v.get("description"):
                            continue

                        v.setdefault("title", "Untitled Finding")
                        v.setdefault("description", v.get("title", "No description"))
                        v.setdefault("vulnerability_type", "Unknown")
                        v.setdefault("severity", "medium")
                        v.setdefault("confidence", 0.5)
                        v.setdefault("location", "Unknown")
                        v.setdefault("file", str(file_path))
                        sev = str(v["severity"]).lower().strip()

                        if sev not in ("critical", "high", "medium", "low"):
                            v["severity"] = "medium"
                        else:
                            v["severity"] = sev

                        try:
                            v["confidence"] = float(v["confidence"])
                        except (ValueError, TypeError):
                            v["confidence"] = 0.5

                        sanitized.append(v)

                    msg_json["vulnerabilities"] = sanitized

                # Ensure field exists even when the model returned a schema definition
                # or other malformed response (e.g. $defs structure instead of findings).
                msg_json.setdefault("vulnerabilities", [])
                vulnerabilities = Vulnerabilities(**msg_json)

                # High-standard models (e.g. grok-4.3) self-apply strict internal criteria
                # and only surface findings they are already very confident about, so their
                # reported confidence scores are systematically lower than what an equivalent
                # finding from a less-strict model would show.  Relax the gate for them so
                # we don't silently discard valid high-confidence findings.
                _is_high_std = (model or PRIMARY_MODEL) in HIGH_STANDARD_MODELS
                _hc_min  = 0.55 if _is_high_std else 0.70
                _med_min = 0.45 if _is_high_std else 0.60
                filtered_vulns = []

                for v in vulnerabilities.vulnerabilities:
                    if v.severity in [Severity.HIGH, Severity.CRITICAL]:
                        if v.confidence >= _hc_min:
                            filtered_vulns.append(v)
                    else:
                        if v.confidence >= _med_min:
                            filtered_vulns.append(v)

                vulnerabilities.vulnerabilities = filtered_vulns

                for v in vulnerabilities.vulnerabilities:
                    v.reported_by_model = (model or PRIMARY_MODEL) + "_" + prompt_name

                input_tokens = response.get('input_tokens', 0) or response.get('usage', {}).get('prompt_tokens', 0)
                output_tokens = response.get('output_tokens', 0) or response.get('usage', {}).get('completion_tokens', 0)
                end_time = time.time()
                time_taken = end_time - start_time

                print(f"[INFO] analyze_file OK   file={relative_path} prompt={prompt_name} vulns={len(vulnerabilities.vulnerabilities)} in={input_tokens} out={output_tokens} t={time_taken:.1f}s")

                if sleep_timeout - time_taken > 0:
                    time.sleep(sleep_timeout - time_taken)

                return vulnerabilities, input_tokens, output_tokens
            except Exception as e:
                print(f"[ERROR] analyze_file FAIL file={relative_path} prompt={prompt_name} attempt={attempt+1} | {type(e).__name__}: {e}")

                # ConnectTimeout, ReadTimeout, and 502/503 HTTPErrors are all treated as
                # unrecoverable — no retry.  Under sustained backend load, retries amplify
                # overload: each retry holds a worker for another 500s, consumes billed
                # tokens on the server, and keeps the backend saturated.  A 502 retry will
                # hit the same overloaded proxy and almost always fail again (confirmed by
                # Genesis.sol SYSTEM_A1 attempt=2 in virtuals-protocol run).
                _is_http_overload = (
                    isinstance(e, requests.exceptions.HTTPError)
                    and e.response is not None
                    and e.response.status_code in (502, 503)
                )
                is_fatal_timeout = isinstance(e, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)) or _is_http_overload

                if attempt < max_retries - 1 and not is_fatal_timeout:
                    time.sleep(2)
                else:
                    return Vulnerabilities(vulnerabilities=[]), 0, 0

    def find_files_to_analyze(self, source_dir: Path, file_patterns: list[str] | None = None) -> list[Path]:
        """Glob for analyzable source files; honours out_of_scope.txt in the repo root to exclude vendor/test paths."""

        if file_patterns:
            files = []

            for pattern in file_patterns:
                files.extend(source_dir.glob(pattern))
        else:
            patterns = ['**/*.sol', '**/*.vy', '**/*.cairo', '**/*.move', '**/*.rs']
            files = []

            for pattern in patterns:
                files.extend(source_dir.glob(pattern))

        ins_paths, ins_prefixes, ins_globs, oos_paths, oos_prefixes, oos_globs = _collect_scope(source_dir)
        _has_allowlist = bool(ins_paths or ins_prefixes or ins_globs)
        _ALWAYS_EXCLUDE = frozenset({'node_modules', '.git', 'artifacts', 'cache', 'out', 'dist', 'build', 'broadcast'})
        _SOFT_EXCLUDE = frozenset({'test', 'tests', 'script', 'scripts', 'mocks', 'mock', 'interfaces', 'lib', 'libraries'})
        exclude_dirs = _ALWAYS_EXCLUDE if _has_allowlist else _ALWAYS_EXCLUDE | _SOFT_EXCLUDE
        files = set(files)
        files = [
            f for f in files

            if f.is_file()
            and not any(part.lower() in exclude_dirs for part in f.parts)
            and (_has_allowlist or not (
                f.name.lower().startswith('test') or
                f.stem.lower().endswith('test') or
                '.t.' in f.name.lower() or
                '.s.' in f.name.lower()
            ))
        ]

        def _glob_match(rel_str: str, patterns: list) -> bool:
            return any(fnmatch.fnmatch(rel_str, p) or fnmatch.fnmatch(rel_str.lower(), p.lower()) for p in patterns)

        # Basename fallback: some contest scope files list bare filenames ("Vault.sol") without
        # a path prefix.  Accept a bare name only when it is unambiguous — i.e. exactly one
        # candidate file has that name — so we don't accidentally admit both src/Vault.sol and
        # lib/Vault.sol when only one was intended.
        _ins_bare_names = {p for p in ins_paths if '/' not in p}
        _name_count: dict[str, int] = {}

        for _f in files:
            _name_count[_f.name.lower()] = _name_count.get(_f.name.lower(), 0) + 1

        _unambiguous_bare_names = {n for n in _ins_bare_names if _name_count.get(n.lower(), 0) <= 1}

        def is_out_of_scope(file_path: Path) -> bool:
            rel = file_path.relative_to(source_dir)
            rel_str = rel.as_posix()
            rel_lower = rel_str.lower()
            parts_lower = [p.lower() for p in rel.parts]

            if _has_allowlist:
                in_scope = (
                    rel_str in ins_paths or rel_lower in ins_paths or
                    _glob_match(rel_str, ins_globs) or
                    file_path.name in _unambiguous_bare_names or
                    file_path.name.lower() in _unambiguous_bare_names
                )

                if not in_scope:
                    for prefix in ins_prefixes:
                        if '/' in prefix:
                            if rel_lower.startswith(prefix + '/') or rel_lower == prefix:
                                in_scope = True; break
                        else:
                            if prefix in parts_lower:
                                in_scope = True; break

                if not in_scope:
                    return True

            if rel_str in oos_paths or rel_lower in oos_paths:
                return True

            for prefix in oos_prefixes:
                if '/' in prefix:
                    if rel_lower.startswith(prefix + '/') or rel_lower == prefix:
                        return True
                else:
                    if prefix in parts_lower:
                        return True

            return _glob_match(rel_str, oos_globs)

        files = [f for f in files if not is_out_of_scope(f)]

        # Drop autogenerated Rust files (kinobi, anchor-build, rust-bindgen, etc.).
        # These are large and produce zero actionable findings.
        _gen_marker = re.compile(
            r'auto[- ]?generated|automatically generated|do not edit|'
            r'this code was autogenerated|this file is generated|code generated by',
            re.IGNORECASE,
        )

        def _is_generated_rs(path: Path) -> bool:
            if path.suffix.lower() != '.rs':
                return False

            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as _f:
                    head = ''.join(next(_f, '') for _ in range(10))
            except Exception:
                return False

            return bool(_gen_marker.search(head))

        files = [f for f in files if not _is_generated_rs(f)]

        def ext_priority(f):
            ext = f.suffix.lower()

            if ext == '.sol':
                return (0, 0)

            if ext == '.vy':
                return (1, 0)

            if ext == '.cairo':
                return (2, 0)

            if ext == '.rs':
                return (3, 0)

            if ext == '.move':
                return (4, 0)

            return (5, str(f).count('/'))

        files = sorted(files, key=ext_priority)

        return files

    def rank_files_by_imports(self, files: list[Path], source_dir: Path) -> list[Path]:
        """Rank files to maximize vulnerability coverage within the 18-file cap.

        Score = graph_centrality + content_surface + name_boost
        - Pure interfaces are pushed to the end (high imports_in but zero logic)
        - Vulnerability surface signals (payable, delegatecall, unchecked, etc.)
          ensure logic-dense files outrank declaration-only files
        - Interface-naming convention (IVault, IRouter) gets a hard penalty
        """

        import_re = re.compile(
            r'^\s*(?:import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']'
            r'|use\s+([A-Za-z0-9_:]+)'
            r'|from\s+([A-Za-z0-9_./]+)\s+import)',
            re.MULTILINE,
        )

        # Depth-sort before setdefault so shallower (production) files win stem
        # slots over deeper test/mock duplicates with the same basename.
        stems = {}

        for f in sorted(files, key=lambda p: len(p.parts)):
            stems.setdefault(f.stem, f)
        _src_root = source_dir.resolve()
        _path_lookup: dict[str, Path] = {}

        for f in files:
            try:
                rel = f.resolve().relative_to(_src_root).as_posix()
                _path_lookup[rel] = f
                _path_lookup[rel.lower()] = f
            except ValueError:
                pass

        imports_out = defaultdict(set)
        imports_in = defaultdict(int)
        file_texts: dict[Path, str] = {}

        for f in files:
            try:
                text = f.read_text(encoding='utf-8', errors='ignore')
                file_texts[f] = text
            except Exception:
                file_texts[f] = ""
                continue

            for m in import_re.finditer(text):
                target = m.group(1) or m.group(2) or m.group(3) or ""

                if not target:
                    continue
                resolved = None

                if '/' in target and not target.startswith('@'):
                    try:
                        cand = (f.parent / target).resolve().relative_to(_src_root).as_posix()
                        resolved = _path_lookup.get(cand) or _path_lookup.get(cand.lower())
                    except (ValueError, OSError):
                        pass

                if resolved is None:
                    tail = Path(re.split(r'[/:]', target.strip())[-1]).stem

                    if tail and tail in stems:
                        resolved = stems[tail]

                if resolved and resolved != f:
                    imports_out[f].add(resolved)
                    imports_in[resolved] += 1

        for f in list(imports_out.keys()):
            transitive = set()

            for dep in imports_out[f]:
                transitive.update(imports_out.get(dep, set()))

            imports_out[f].update(transitive - {f})

        imports_in = defaultdict(int)

        for f, deps in imports_out.items():
            for dep in deps:
                imports_in[dep] += 1

        _role_re = re.compile(
            r'(?i)(strateg|vault|router|registry|controller|manager|executor|pool'
            r'|staking|reward|validator|token|nft|bridge|oracle|lending|borrow'
            r'|swap|liquidat|governor|treasury|escrow|dispatch|multicall|multi'
            r'|inference)',
        )
        _base_re = re.compile(r'(?i)(base|core|main|impl|logic|abstract)')
        _iface_name_re = re.compile(r'^I[A-Z]')  # IVault, IRouter, IPool …

        def _is_pure_interface(text: str) -> bool:
            has_iface_kw = bool(re.search(r'^\s*interface\s+\w+', text, re.MULTILINE))
            fn_bodies = len(re.findall(r'\bfunction\b[^;{]*\{', text))
            fn_sigs   = len(re.findall(r'\bfunction\b[^;{]*;',  text))

            if has_iface_kw and fn_bodies == 0 and fn_sigs > 0:
                return True

            if fn_sigs > 0 and fn_bodies == 0:
                return True

            if fn_sigs > fn_bodies * 4:
                return True

            return False

        def _content_score(text: str) -> int:
            if not text:
                return 0

            s = 0

            # ETH / value flow
            s += min(text.count('payable'),     6) * 2
            s += min(text.count('@payable'),     4) * 2   # Vyper

            # External call risk
            s += min(text.count('delegatecall'), 4) * 5
            s += min(text.count('.call{'),       4) * 4
            s += min(text.count('.call('),       4) * 3

            # Low-level / unsafe code
            s += min(text.count('assembly'),     4) * 4
            s += min(text.count('unchecked'),    6) * 2
            s += min(text.count('abi.encode'),   4) * 1

            # Token operations
            s += min(text.count('transferFrom'), 4) * 2
            s += min(text.count('safeTransfer'), 4) * 2
            s += min(text.count('approve'),      4) * 2

            # Storage / state surface
            s += min(text.count('mapping('),     6) * 1

            # Implementation density (bodies vs. bare signatures)
            fn_bodies = len(re.findall(r'\bfunction\b[^;{]*\{', text))
            fn_sigs   = len(re.findall(r'\bfunction\b[^;{]*;',  text))
            total_fns = fn_bodies + fn_sigs

            if total_fns > 0:
                s += int((fn_bodies / total_fns) * 6)  # 0–6 based on impl ratio

            # For-loop + token transfer = array-based fund distribution (high routing-bug risk)
            for_count = text.count('for (') + text.count('for(')
            if for_count > 0 and (text.count('safeTransfer') + text.count('transferFrom')) > 0:
                s += 4

            return s

        def _name_boost(f: Path) -> int:
            name = f.stem

            if _iface_name_re.match(name):
                return -10  # hard penalty for IVault / IRouter naming convention

            role  = len(_role_re.findall(name)) * 5
            base  = len(_base_re.findall(name)) * 4

            try:
                size_kb = f.stat().st_size / 1024
                size_bonus = min(int(size_kb / 5), 5)  # modest cap — size alone ≠ value
            except Exception:
                size_bonus = 0

            return role + base + size_bonus

        def score(f: Path) -> tuple:
            text  = file_texts.get(f, "")

            if _is_pure_interface(text):
                return (999, f.suffix != '.sol', str(f))  # always after real contracts

            graph   = imports_in[f] * 2 + len(imports_out[f])
            content = _content_score(text)
            name    = _name_boost(f)

            return (-(graph + content + name), f.suffix != '.sol', str(f))

        return sorted(files, key=score)

    def find_related_files(self, file_path: Path, files_in_scope: list[Path], source_dir: Path, import_graph: dict | None = None) -> list[str]:
        """Return paths (relative strings) of files that import or are imported by file_path.
        Uses the pre-computed import graph from rank_files_by_imports when available,
        otherwise falls back to a quick grep of the file's own import statements."""

        related: list[str] = []

        if import_graph is not None:
            related = [str(p.relative_to(source_dir)) for p in import_graph.get(file_path, [])]
        else:
            try:
                text = file_path.read_text(encoding='utf-8', errors='ignore')
                import_re = re.compile(
                    r'^\s*(?:import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']'
                    r'|use\s+([A-Za-z0-9_:]+)|from\s+([A-Za-z0-9_./]+)\s+import)',
                    re.MULTILINE,
                )
                _src_root = source_dir.resolve()
                _path_lookup: dict[str, Path] = {}

                for _f in files_in_scope:
                    try:
                        _rel = _f.resolve().relative_to(_src_root).as_posix()
                        _path_lookup[_rel] = _f
                        _path_lookup[_rel.lower()] = _f
                    except ValueError:
                        pass

                stems = {f.stem: f for f in files_in_scope}

                for m in import_re.finditer(text):
                    raw = (m.group(1) or m.group(2) or m.group(3) or "").strip()
                    resolved = None

                    if '/' in raw and not raw.startswith('@'):
                        try:
                            cand = (file_path.parent / raw).resolve().relative_to(_src_root).as_posix()
                            resolved = _path_lookup.get(cand) or _path_lookup.get(cand.lower())
                        except (ValueError, OSError):
                            pass

                    if resolved is None:
                        tail = Path(re.split(r'[/:]', raw)[-1]).stem

                        if tail and tail in stems:
                            resolved = stems[tail]

                    if resolved and resolved != file_path:
                        related.append(str(resolved.relative_to(source_dir)))
            except Exception:
                pass

        return related[:5]

    def _llm_cluster_chunk(self, chunk: list, model: str) -> list:
        """Ask the LLM to identify duplicate groups within one chunk of findings.
        Returns list[list[Vulnerability]]. On failure, raises — caller falls back to heuristic."""

        if len(chunk) < 2:
            return [[v] for v in chunk]

        findings_text = ""

        for i, v in enumerate(chunk):
            sev = v.severity.value if v.severity else "high"
            findings_text += (
                f"[{i}] file: {v.file}\n"
                f"    type: {v.vulnerability_type}\n"
                f"    severity: {sev}  conf: {v.confidence}\n"
                f"    location: {v.location}\n"
                f"    title: {v.title}\n"
                f"    description: {v.description[:300]}\n\n"
            )

        system_msg = (
            "You are a smart contract security expert. Identify DUPLICATE findings — same underlying bug, "
            "same exploit path, or same root cause stated differently. "
            "Be strict: when in doubt, keep findings separate. Respond with ONLY valid JSON, no prose."
        )
        user_msg = (
            f"Below are {len(chunk)} findings. Identify duplicates.\n\n{findings_text}\n"
            "Output schema: {\"duplicate_groups\": [[0, 3, 7], [2, 5], ...]}\n"
            "Each inner list = indices of duplicates (2+). "
            "Findings NOT in any group remain singletons. "
            "If no duplicates: {\"duplicate_groups\": []}"
        )
        response = self.inference(
            messages=[{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
            model=model, timeout=180, call_type="llm_cluster", file=chunk[0].file,
        )
        content = (response.get('content') or response.get('choices', [{}])[0].get('message', {}).get('content') or '').strip()

        if not content:
            raise ValueError("empty content")

        if content.startswith("```"):
            lines = content.splitlines()
            lines = lines[1:] if lines and lines[0].startswith("```") else lines
            lines = lines[:-1] if lines and lines[-1].strip() == "```" else lines
            content = "\n".join(lines).strip()

        json_match = re.search(r'\{.*\}', content, re.DOTALL)

        if not json_match:
            raise ValueError("no JSON object found")

        parsed = json.loads(json_match.group())
        duplicate_groups = parsed.get('duplicate_groups', [])

        if not isinstance(duplicate_groups, list):
            raise ValueError("duplicate_groups not a list")

        clusters = []
        consumed = set()

        for group in duplicate_groups:
            if not isinstance(group, list) or len(group) < 2:
                continue

            valid = [i for i in group if isinstance(i, int) and 0 <= i < len(chunk) and i not in consumed]

            if len(valid) < 2:
                continue

            clusters.append([chunk[i] for i in valid])
            consumed.update(valid)

        for i in range(len(chunk)):
            if i not in consumed:
                clusters.append([chunk[i]])

        return clusters

    def llm_cluster_findings(self, vulns: list, model: str, timeout: int = 200) -> list:
        """Cluster all findings via LLM batch calls (chunked). Falls back to heuristic on failure.
        Returns list[list[Vulnerability]]."""

        n = len(vulns)

        if n < 5:
            return [[v] for v in vulns]

        sorted_vulns = sorted(vulns, key=lambda v: (
            v.file or "",
            _normalize_text(v.vulnerability_type or ""),
            (v.title or "").lower(),
        ))

        CHUNK = 25
        chunks = [sorted_vulns[i:i + CHUNK] for i in range(0, n, CHUNK)]
        chunk_clusters = []
        chunk_failures = 0
        cluster_deadline = time.time() + timeout
        cluster_ex = ThreadPoolExecutor(max_workers=6)

        try:
            futs = {cluster_ex.submit(self._llm_cluster_chunk, ch, model): ch for ch in chunks}

            try:
                for f in as_completed(futs, timeout=max(1.0, cluster_deadline - time.time())):
                    ch = futs[f]

                    try:
                        clusters = f.result()
                    except Exception:
                        chunk_failures += 1
                        clusters = cluster_findings(list(ch))

                    chunk_clusters.extend(clusters)
            except (TimeoutError, FuturesTimeoutError):
                for fut, ch in futs.items():
                    if not fut.done():
                        fut.cancel()
                        chunk_failures += 1
                        chunk_clusters.extend(cluster_findings(list(ch)))
        finally:
            cluster_ex.shutdown(wait=False, cancel_futures=True)

        final = _merge_clusters_across_chunks(chunk_clusters)
        print(
            f"[cluster] raw={n} chunks={len(chunks)} failures={chunk_failures} "
            f"intra={len(chunk_clusters)} final_LLM={len(final)}",
            flush=True,
        )

        return final

    def _llm_merge_cluster(self, cluster: list, model: str) -> list:
        """Ask the LLM to merge a cluster of similar findings into 1+ canonical findings.
        Returns list of Vulnerability objects. On any failure, falls back to heuristic _merge_group."""

        if len(cluster) <= 1:
            return list(cluster)

        chunk_cap = 12

        if len(cluster) > chunk_cap:
            results = []

            for i in range(0, len(cluster), chunk_cap):
                results.extend(self._llm_merge_cluster(cluster[i:i+chunk_cap], model))

            return results

        findings_text = ""

        for i, v in enumerate(cluster):
            sev = v.severity.value if v.severity else "high"
            findings_text += (
                f"[{i}] title: {v.title}\n"
                f"    type: {v.vulnerability_type}\n"
                f"    severity: {sev}  confidence: {v.confidence}\n"
                f"    file: {v.file}  location: {v.location}\n"
                f"    description: {v.description[:400]}\n"
                f"    reported_by: {v.reported_by_model}\n\n"
            )

        system_msg = (
            "You are a smart contract security expert. You receive a cluster of findings that a heuristic "
            "step grouped together as similar. Your job: produce the canonical set that should appear in the final report.\n\n"
            "Rules:\n"
            "- If all describe the SAME root cause -> return 1 merged finding combining their unique technical details.\n"
            "- If they describe K DISTINCT root causes (different invariants / different code paths / different impact) -> return K findings.\n"
            "- NEVER return more findings than were given in the cluster.\n"
            "- Default to merging unless you are confident the issues are genuinely distinct.\n"
            "- For each output: pick the highest severity and highest confidence among its source findings.\n"
            "- Combine descriptions: keep unique technical details, drop verbatim repetition.\n"
            "Respond with ONLY valid JSON, no prose."
        )
        user_msg = (
            f"Cluster of {len(cluster)} similar findings:\n\n{findings_text}\n"
            "Output JSON schema:\n"
            "{\n"
            '  "merged": [\n'
            '    {"title": "...", "description": "...", "vulnerability_type": "...",\n'
            '     "severity": "critical|high|medium|low", "confidence": 0.0,\n'
            '     "location": "...", "file": "...", "source_indices": [0]}\n'
            "  ]\n"
            "}"
        )

        try:
            response = self.inference(
                messages=[{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
                model=model, timeout=180, call_type="llm_merge", file=cluster[0].file,
            )
            content = response.get('content', '') or response.get('choices', [{}])[0].get('message', {}).get('content', '')

            if not content:
                raise ValueError("empty content")

            content = content.strip()

            if content.startswith("```"):
                lines = content.splitlines()

                if lines and lines[0].startswith("```"):
                    lines = lines[1:]

                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                content = "\n".join(lines).strip()

            json_match = re.search(r'\{.*\}', content, re.DOTALL)

            if not json_match:
                raise ValueError("no JSON object found")

            parsed = json.loads(json_match.group())
            merged_list = parsed.get('merged', [])

            if not isinstance(merged_list, list) or not merged_list:
                raise ValueError("empty merged list")

            if len(merged_list) > len(cluster):
                merged_list = merged_list[:len(cluster)]

            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            best_member = max(cluster, key=lambda v: v.confidence)
            output = []

            for entry in merged_list:
                if not isinstance(entry, dict):
                    continue

                title = (entry.get('title') or best_member.title).strip()
                description = (entry.get('description') or best_member.description).strip()
                vtype = (entry.get('vulnerability_type') or best_member.vulnerability_type).strip()
                sev_str = (entry.get('severity') or "high").lower().strip()
                severity = sev_map.get(sev_str, best_member.severity)

                try:
                    confidence = float(entry.get('confidence', best_member.confidence))
                except (TypeError, ValueError):
                    confidence = best_member.confidence

                # Clamp only — no cluster-size boost.  Inflating by consensus count
                # distorts ranking and over-promotes noisy duplicates over high-evidence
                # singletons that simply didn't recur across prompts.
                confidence = max(0.0, min(1.0, confidence))
                location = (entry.get('location') or best_member.location).strip()
                file_field = (entry.get('file') or best_member.file).strip()
                source_models = sorted(set(v.reported_by_model for v in cluster if v.reported_by_model))
                reported_by = f"merged_via_235b<-{','.join(source_models)}" if source_models else "merged_via_235b"
                output.append(Vulnerability(
                    title=title, description=description, vulnerability_type=vtype,
                    severity=severity, confidence=confidence, location=location,
                    file=file_field, reported_by_model=reported_by,
                    root_cause=best_member.root_cause,
                    fix_location=best_member.fix_location,
                    violated_invariant=best_member.violated_invariant,
                ))

            if not output:
                raise ValueError("no valid entries parsed")

            return output
        except Exception:
            return [_merge_group(list(cluster))]

    def llm_merge_findings(self, vulns: list, model: str, timeout: int = 170) -> list:
        """2-step merge: LLM cluster all findings first, then LLM-merge each multi-cluster.
        Singletons pass through untouched. Falls back to heuristic clustering on LLM failure.
        Uses JSON_MODEL (non-reasoning) for both cluster and merge steps.
        timeout: hard wall-clock budget in seconds for the entire merge phase."""

        if not vulns:
            return vulns

        deadline = time.time() + timeout

        # Step 1: LLM clustering (uses JSON_MODEL, not the reasoning analysis model)
        try:
            cluster_timeout = max(10, int(deadline - time.time()) - 10)
            clusters = self.llm_cluster_findings(vulns, model=JSON_MODEL, timeout=cluster_timeout)
        except Exception:
            clusters = cluster_findings(vulns)

        merged = []
        merge_futures: dict = {}
        processed: set = set()
        n_raw = len(vulns)
        multi_clusters = sum(1 for c in clusters if len(c) > 1)

        # Scale merge workers with finding count — more findings need more parallel merges.
        if n_raw < 600:
            _merge_workers = 12
        elif n_raw < 1000:
            _merge_workers = 16
        else:
            _merge_workers = 20

        _merge_workers = min(_merge_workers, max(multi_clusters, 1))

        # Step 2: LLM merge per cluster (also uses JSON_MODEL)
        executor = ThreadPoolExecutor(max_workers=_merge_workers)

        try:
            for cluster in clusters:
                if len(cluster) == 1:
                    merged.append(cluster[0])
                else:
                    merge_futures[executor.submit(self._llm_merge_cluster, cluster, JSON_MODEL)] = cluster

            try:
                for fut in as_completed(merge_futures, timeout=max(1.0, deadline - time.time())):
                    processed.add(fut)
                    cluster = merge_futures[fut]

                    try:
                        result = fut.result(timeout=max(1.0, deadline - time.time()))
                        merged.extend(result)
                    except Exception:
                        merged.append(_merge_group(list(cluster)))
            except Exception:
                pass

            for fut, cluster in merge_futures.items():
                if fut not in processed:
                    merged.append(_merge_group(list(cluster)))
        finally:
            for fut in merge_futures:
                if fut not in processed:
                    fut.cancel()

            executor.shutdown(wait=False, cancel_futures=True)

        return merged

    def _run_protocol_model(self, source_dir: Path, relative_path: str) -> dict:
        """Classify a single file's security profile using THINKING_MODEL.
        Returns dict with keys: role, is_high_risk, skip_prompts, notes. Returns {} on failure."""

        try:
            content = read_file_text(source_dir / relative_path)
            content_preview = content[:8000]
            messages = [
                {"role": "system", "content": PROTOCOL_MODEL_PROMPT},
                {"role": "user", "content": f"File: {relative_path}\n```\n{content_preview}\n```"},
            ]
            _proto_dl = getattr(self, '_proto_deadline', None)
            if _proto_dl is not None and time.time() >= _proto_dl:
                return {}  # split deadline passed — skip classification
            # 300s per call: keeps each classification within the proxy timeout.
            # Phase 0 runs serially in the background overlapping with Phase 1.
            _proto_timeout = min(300, max(5, int(_proto_dl - time.time()))) if _proto_dl is not None else 300
            resp = self.inference(
                messages=messages, model=THINKING_MODEL, timeout=_proto_timeout,
                call_type="protocol_model", file=relative_path, thinking_budget=1024,
            )
            content_str = (resp.get("content") or resp.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            data = self.clean_json_response(content_str)

            if isinstance(data, dict) and "role" in data:
                print(f"[protocol_model] file={relative_path} role={data.get('role')} high_risk={data.get('is_high_risk')} skip={data.get('skip_prompts', [])}")
                return data
        except Exception as exc:
            print(f"[protocol_model] FAIL file={relative_path}: {type(exc).__name__}: {exc}")

        return {}

    def _select_prompts_for_file(self, relative_path: str, protocol_output: dict) -> list[tuple[str, str]]:
        """Return (prompt_name, prompt_text) pairs to run for this file in Phases 2 and 3.
        Tier 2 prompts are handled separately (with thinking ON); this selects Tier 3 and Tier 4 only.

        Filtering layers (applied in order):
        1. protocol model skip_prompts  — explicit skips from THINKING_MODEL analysis
        2. _ROLE_EXTRA_SKIPS            — structural skips based on file role
        3. is_high_risk gate            — general Tier 4 requires high-risk classification
        4. role/notes gate              — TIER4_ROLE_TARGETED prompts run only on role/notes match
        5. file-suffix gate             — Solidity-only prompts check file extension
        """

        role = protocol_output.get("role", "other")
        skip_set = set(protocol_output.get("skip_prompts", []))
        skip_set |= _ROLE_EXTRA_SKIPS.get(role, frozenset())
        is_high_risk = protocol_output.get("is_high_risk", True)
        suffix = Path(relative_path).suffix.lower()
        is_solidity = suffix in SOLIDITY_FAMILY_SUFFIXES
        positive_includes = set(_ROLE_POSITIVE_INCLUDES.get(role, frozenset()))

        # Notes-based keyword expansion — recall safety net for files classified as "other"
        # (or any unexpected role) whose protocol model notes mention DEX/AMM or math content.
        # This prevents a role misclassification from silently dropping specialist coverage.
        # Applied after role lookup so that explicitly-matched roles are unchanged.
        _notes = protocol_output.get("notes", "").lower()
        _DEX_NOTES  = {"swap", "liquidity", "amm", "dex", "pool", "stableswap", "invariant",
                       "velodrome", "uniswap", "curve", "aerodrome", "concentrated", "tick"}
        _MATH_NOTES = {"fixed-point", "fixed_point", "sqrt", "logarithm", "arithmetic",
                       "mantissa", "exponent", "float", "precision", "rounding", "transcendental"}
        # Business-logic lifecycle keywords — force PROMPT_SYMMETRY on vesting / migration /
        # rental / marketplace contracts so the lateral-transfer and inverse-completeness
        # checks run even when the file is classified as a generic "other" low-risk role.
        # PROMPT_LIFECYCLE is already Tier 3 (always runs); only PROMPT_SYMMETRY needs forcing.
        # Intentionally narrow: broad verbs like "transfer", "lock", "bid", "cancel" are
        # excluded because they appear in the Phase 0 notes of ordinary token/vault contracts
        # and would over-trigger once the routing fix below makes this set actually live.
        _BUSINESS_NOTES = {"vesting", "migrat", "rental", "lease",
                           "unlock", "schedule", "epoch",
                           "expir", "grace", "deprecat", "marketplace"}
        if any(k in _notes for k in _DEX_NOTES):
            positive_includes |= {"PROMPT_DEX_INTEGRATION", "PROMPT_ARITHMETIC"}
        elif any(k in _notes for k in _MATH_NOTES):
            positive_includes |= {"PROMPT_ARITHMETIC"}
        if any(k in _notes for k in _BUSINESS_NOTES):
            positive_includes |= {"PROMPT_SYMMETRY"}

        # Protocol-model miss fallback: when protocol_output is empty (Phase 0 timeout
        # or parse failure), role="other" and notes="" so the role/notes safety net above
        # never activates.  Rather than silently dropping specialist prompts for an
        # unknown file, include all TIER4_ROLE_TARGETED prompts when is_high_risk is True
        # (which also defaults to True on empty output).  This errs on recall for unknown
        # files while still saving budget on files that have a valid low-risk classification.
        if not protocol_output.get("role") and is_high_risk:
            positive_includes |= set(TIER4_ROLE_TARGETED_NAMES)

        selected = []

        for name, prompt in TOOL_LIST.items():
            if name in skip_set:
                continue

            if name in TIER2_PROMPT_NAMES:
                continue  # handled separately in Phase 1 with thinking ON

            if name in TIER3_PROMPT_NAMES:
                selected.append((name, prompt))
            elif name in TIER4_PROMPT_NAMES:
                # is_high_risk is the normal gate; positive_includes can force a Tier 4 prompt
                # even on a low-risk file when notes-based keyword expansion fires (e.g.
                # PROMPT_SYMMETRY forced on vesting/migration/rental files).
                if is_high_risk or name in positive_includes:
                    selected.append((name, prompt))
            elif name in TIER4_ROLE_TARGETED_NAMES:
                # Role-targeted specialist prompts: fire on role/notes match only.
                # is_high_risk alone is not sufficient — governance, factory, and multicall
                # files can be high-risk without needing DEX/math specialist passes.
                if name in positive_includes:
                    selected.append((name, prompt))
            elif name in TIER4_SOLIDITY_NAMES:
                if is_solidity:
                    selected.append((name, prompt))

        return selected

    def _run_verifier_soft_rank(self, vulns: list, source_dir: Path, deadline: float, file_rank_order: list[str] | None = None) -> list:
        """Adjust confidence scores using THINKING_MODEL as a soft verifier.
        Applies delta adjustments: +0.10 (strong evidence) | 0.0 (uncertain) | -0.20 (likely FP).
        Removes a finding only if its adjusted confidence drops below 0.40.
        Groups by file and runs in parallel; falls back to pass-through on failure."""

        if not vulns:
            return vulns

        VERIFIER_SYSTEM = (
            "You are a smart contract security expert reviewing audit findings for false-positive risk.\n"
            "For each finding, assign a confidence adjustment:\n"
            "  +0.10 : strong concrete evidence, the bug is clearly real\n"
            "   0.00 : uncertain or borderline\n"
            "  -0.20 : likely false positive — clearly handled by existing code, or attack path impossible\n\n"
            "Apply -0.20 ONLY when you are confident the finding is a false positive. When in doubt use 0.00.\n"
            "CRITICAL: never suppress a finding just because the bug class is common or because you haven't "
            "verified the full codebase. Err on the side of keeping findings.\n"
            "Respond with ONLY valid JSON:\n"
            "{\"adjustments\": [{\"index\": <N>, \"delta\": <+0.10|0.00|-0.20>, \"reason\": \"<one line>\"}]}"
        )

        by_file: dict[str, list] = defaultdict(list)

        for v in vulns:
            by_file[v.file].append(v)

        # Sort files by importance (original scan rank), skip empty, cap at 6 verified.
        # Files ranked lower than the cap pass through untouched so no findings are lost.
        if file_rank_order:
            rank_idx = {f: i for i, f in enumerate(file_rank_order)}
            candidate_files = sorted(
                [(fp, fv) for fp, fv in by_file.items() if fv],
                key=lambda x: rank_idx.get(x[0], len(file_rank_order)),
            )
        else:
            candidate_files = [(fp, fv) for fp, fv in by_file.items() if fv]

        _VERIFIER_CAP = 6
        adjusted_all: list = []
        removed_count = 0

        for fp, fv in candidate_files[_VERIFIER_CAP:]:
            adjusted_all.extend(fv)

        files_to_verify = candidate_files[:_VERIFIER_CAP]
        verifier_ex = ThreadPoolExecutor(max_workers=5)
        v_futures: dict = {}

        def _verify_file(file_path: str, file_vulns: list) -> list:
            nonlocal removed_count

            try:
                file_content = ""

                try:
                    file_content = read_file_text(source_dir / file_path)[:6000]
                except Exception:
                    pass

                findings_text = ""

                for i, v in enumerate(file_vulns):
                    findings_text += (
                        f"[{i}] title: {v.title}\n"
                        f"    type: {v.vulnerability_type}\n"
                        f"    confidence: {v.confidence:.2f}\n"
                        f"    desc: {v.description[:300]}\n\n"
                    )

                user_msg = (
                    f"File: {file_path}\n```\n{file_content}\n```\n\n"
                    f"Findings to verify ({len(file_vulns)} total):\n{findings_text}"
                )
                resp = self.inference(
                    messages=[{"role": "system", "content": VERIFIER_SYSTEM}, {"role": "user", "content": user_msg}],
                    model=THINKING_MODEL, timeout=650, call_type="verifier", file=file_path, thinking_budget=2048,
                )
                content_str = (resp.get("content") or resp.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                data = self.clean_json_response(content_str)
                adjustments: dict[int, float] = {
                    a["index"]: float(a.get("delta", 0.0))

                    for a in data.get("adjustments", [])

                    if isinstance(a, dict) and isinstance(a.get("index"), int)
                }
                result = []

                for i, v in enumerate(file_vulns):
                    delta = adjustments.get(i, 0.0)
                    v.confidence = clamp(v.confidence + delta, 0.0, 1.0)

                    if v.confidence >= 0.40:
                        result.append(v)
                    else:
                        print(f"[verifier] removed '{v.title[:60]}' conf={v.confidence:.2f} delta={delta:+.2f}")

                return result
            except Exception as exc:
                print(f"[verifier] FAIL file={file_path}: {type(exc).__name__}: {exc}")
                return list(file_vulns)

        processed_v_futures: set = set()

        try:
            for file_path, file_vulns in files_to_verify:
                if time.time() >= deadline:
                    adjusted_all.extend(file_vulns)
                    continue

                v_futures[verifier_ex.submit(_verify_file, file_path, file_vulns)] = file_path

            remaining = max(1.0, deadline - time.time())

            for fut in as_completed(v_futures, timeout=remaining):
                processed_v_futures.add(fut)
                try:
                    adjusted_all.extend(fut.result())
                except Exception:
                    adjusted_all.extend(by_file[v_futures[fut]])
        except (TimeoutError, FuturesTimeoutError):
            for fut, fp in v_futures.items():
                if fut in processed_v_futures:
                    continue
                fut.cancel()
                try:
                    adjusted_all.extend(fut.result() if fut.done() else by_file[fp])
                except Exception:
                    adjusted_all.extend(by_file[fp])
        finally:
            verifier_ex.shutdown(wait=False, cancel_futures=True)

        print(f"[verifier] input={len(vulns)} output={len(adjusted_all)} removed={len(vulns)-len(adjusted_all)}", flush=True)

        return adjusted_all

    def analyze_project(self, source_dir: Path, project_name: str, file_patterns: list[str] | None = None) -> AnalysisResult:
        """Orchestrate the 28-minute audit pipeline.

        Deadlines: scan=21 min | verifier=24 min | merge=28 min
        The verifier runs when >60 s remain before verifier_deadline; merge gets
        whatever is left.  Deferred Phase 1/2 collection may consume part of the
        verifier window, so the effective verifier and merge slots vary per run.

        Phase 0 : Protocol model on all ranked files (THINKING_MODEL, serial background)
        Phase 1 : Tier 2 breadth — A1-A4, B for all files, thinking_budget=2048
        Phase 2 : Tier 3-4 depth — role-filtered prompts per file, JSON_MODEL
        Phase 4 : Agentic deep-dive on top-5 files (ROUTER_MODEL) — runs BEFORE Phase 3;
                  requires ≥90 s remaining so the deep-dive is never starved by Phase 3
        Phase 3 : Two-pass at temperature=0.15 for recall diversity — runs only if
                  ≥120 s remain after Phase 4; lower priority than the deep-dive
        Phase 5 : Verifier soft rank — THINKING_MODEL adjusts confidence, removes sub-0.40
        Phase 6 : Per-file cap → LLM merge → output cap at 100
        """

        import random

        start_time = time.time()

        # Deadlines: scan=24.5 min, verifier=27.5 min, total=29 min (effective windows vary — see docstring).
        scan_deadline = start_time + 1470  # 24 min 30 s
        verifier_deadline = start_time + 1650  # 27 min 30 s
        total_deadline   = start_time + 29 * 60

        # Expose deadlines so inference() can cap HTTP timeouts dynamically.
        # Prevents daemon worker threads from billing OpenRouter past the budget.
        self._scan_deadline       = scan_deadline
        self._collection_deadline = scan_deadline + 90  # deferred Phase 1/2 collection window
        self._total_deadline      = total_deadline

        max_files_to_analyze = 30
        files = self.find_files_to_analyze(source_dir, file_patterns)
        files = self.rank_files_by_imports(files, source_dir)
        readme_path = source_dir / "README.md"
        readme_content = ""

        if readme_path.exists() and readme_path.is_file():
            try:
                with open(readme_path, "r", encoding="utf-8") as readme_file:
                    readme_content = readme_file.read()
            except Exception:
                pass

        num_files = len(files[:max_files_to_analyze])
        file_cap = min(18, num_files)
        files_skipped = num_files - file_cap
        use_two_pass = os.getenv('TWO_PASS', 'false').lower() != 'false'
        max_threads = 12
        ranked_files = files[:file_cap]

        if not ranked_files:
            return AnalysisResult(
                project=project_name,
                timestamp=datetime.now().isoformat(),
                files_analyzed=0,
                files_skipped=files_skipped,
                total_vulnerabilities=0,
                vulnerabilities=[],
                token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0},
            )

        # Build import graph once for related-file lookup.
        import_re = re.compile(
            r'^\s*(?:import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']'
            r'|use\s+([A-Za-z0-9_:]+)|from\s+([A-Za-z0-9_./]+)\s+import)',
            re.MULTILINE,
        )
        file_texts: dict[Path, str] = {}
        stems: dict[str, Path] = {}

        for f in sorted(ranked_files, key=lambda p: len(p.parts)):
            stems.setdefault(f.stem, f)
        _src_root = source_dir.resolve()
        _path_lookup: dict[str, Path] = {}

        for f in ranked_files:
            try:
                rel = f.resolve().relative_to(_src_root).as_posix()
                _path_lookup[rel] = f
                _path_lookup[rel.lower()] = f
            except ValueError:
                pass

        for f in ranked_files:
            try:
                file_texts[f] = f.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                file_texts[f] = ""

        # Project-level Rust chain flavor detection.
        # Check Cargo.toml first (most reliable), then fall back to scanning file texts.
        # Used to correctly frame helper/state Rust modules that don't import chain crates
        # directly (e.g. state.rs, msg.rs in a CosmWasm project).
        # Limitation: a single flavor is applied to the whole project. Mixed Cargo workspaces
        # (multiple member crates with different chain dependencies) are not modelled here;
        # in that case the fallback is "" (empty), which lets file-level detection handle each
        # file independently — no wrong framing, but some helper modules fall to rs_generic.
        _rs_flavor = ""
        _cargo = source_dir / "Cargo.toml"
        if _cargo.exists():
            try:
                _cargo_text = _cargo.read_text(encoding='utf-8', errors='ignore')
                if 'cosmwasm-std' in _cargo_text or 'cosmwasm_std' in _cargo_text:
                    _rs_flavor = "cosmwasm"
                elif 'anchor-lang' in _cargo_text or 'anchor_lang' in _cargo_text:
                    _rs_flavor = "anchor"
            except Exception:
                pass

        if not _rs_flavor:
            for _f, _txt in file_texts.items():
                if _f.suffix != '.rs':
                    continue
                if 'use cosmwasm_std' in _txt or '#[entry_point]' in _txt or 'use cw_storage_plus' in _txt:
                    _rs_flavor = "cosmwasm"
                    break
                if 'anchor_lang' in _txt or '#[program]' in _txt or 'declare_id!' in _txt:
                    _rs_flavor = "anchor"
                    break

        if _rs_flavor:
            print(f"[project] detected Rust flavor: {_rs_flavor}")

        import_graph_raw: dict[Path, set[Path]] = {f: set() for f in ranked_files}

        for f in ranked_files:
            for m in import_re.finditer(file_texts.get(f, "")):
                target = m.group(1) or m.group(2) or m.group(3) or ""

                if not target:
                    continue

                resolved = None
                if '/' in target and not target.startswith('@'):
                    try:
                        cand = (f.parent / target).resolve().relative_to(_src_root).as_posix()
                        resolved = _path_lookup.get(cand) or _path_lookup.get(cand.lower())
                    except (ValueError, OSError):
                        pass

                if resolved is None:
                    tail = Path(re.split(r'[/:]', target.strip())[-1]).stem

                    if tail and tail in stems:
                        resolved = stems[tail]

                if resolved and resolved != f:
                    import_graph_raw[f].add(resolved)

        for f in list(import_graph_raw.keys()):
            transitive = set()

            for dep in import_graph_raw[f]:
                transitive.update(import_graph_raw.get(dep, set()))

            import_graph_raw[f].update(transitive - {f})

        import_graph: dict[Path, list[Path]] = {f: list(deps) for f, deps in import_graph_raw.items()}
        file_related: dict[str, list[str]] = {}

        for file_path in ranked_files:
            relative_path = str(file_path.relative_to(source_dir))
            file_related[relative_path] = self.find_related_files(file_path, ranked_files, source_dir, import_graph)

        all_vulnerabilities: list = []
        total_input_tokens = 0
        total_output_tokens = 0
        future_meta: dict = {}
        file_futures_done: dict = defaultdict(int)
        executor = ThreadPoolExecutor(max_workers=max_threads)

        def _fmt_protocol_context(proto_out: dict) -> str:
            if not proto_out:
                return ""

            role = proto_out.get("role", "")
            is_hr = proto_out.get("is_high_risk", True)
            notes = proto_out.get("notes", "")
            parts = [f"File role: {role}", f"High-risk: {is_hr}"]

            if notes:
                parts.append(f"Notes: {notes}")

            return " | ".join(parts)

        def _submit_analyze(rel_path, related, tool_name, tool_prompt, mdl=None, tb=0, temp=0.01, pctx=None):
            # Skip if < PHASE4_RESERVE seconds remain until scan_deadline.
            _scan_remaining = int(scan_deadline - time.time())
            if _scan_remaining < PHASE4_RESERVE:
                return None

            # Timeout = time until the deferred-collection window closes (scan_deadline + 90s).
            # Caps at 650s so early calls are not penalised.  Late calls get a tighter cap
            # so they don't keep running past the point where their result can still be collected.
            _effective_timeout = min(650, _scan_remaining + 90)

            f = executor.submit(
                self.analyze_file, source_dir, rel_path, related,
                model=mdl or PRIMARY_MODEL, system_prompt=tool_prompt,
                prompt_name=tool_name, context=readme_content, sleep_timeout=0,
                inference_timeout=_effective_timeout,
                temperature=temp, thinking_budget=tb, protocol_context=pctx,
                rs_flavor=_rs_flavor,
            )
            future_meta[f] = (rel_path, tool_name)

            return f

        processed_scan_futures: set = set()

        def _collect(future):
            nonlocal total_input_tokens, total_output_tokens

            if future in processed_scan_futures:
                return
            processed_scan_futures.add(future)

            try:
                vulns_obj, inp_tok, out_tok = future.result(timeout=360)
                total_input_tokens += inp_tok
                total_output_tokens += out_tok
                fmeta = future_meta.get(future, ("unknown", "unknown"))
                file_futures_done[fmeta[0]] += 1

                if vulns_obj:
                    all_vulnerabilities.extend(vulns_obj.vulnerabilities)
            except Exception:
                pass

        try:
            # ----------------------------------------------------------------
            # Phase 0: Protocol model for ALL ranked files — background parallel.
            # max_workers=2: THINKING_MODEL (qwen3-235b-a22b-thinking-2507) handles
            # 2 concurrent requests without triggering 502s on the upstream provider.
            #
            # Phase 0 runs concurrently with Phase 1 — THINKING_MODEL and
            # PRIMARY_MODEL route to different upstream providers so they do not
            # compete.  Results are consumed as a snapshot at Phase 2/4 submission
            # time via _get_proto_out(): if a file's future is done when Phase 2 is
            # submitted (~8 min in), that file gets protocol context; otherwise it
            # falls back to defaults.  Early-ranked files benefit most because Phase 0
            # processes files in ranked order and Phase 2 is submitted after the
            # Phase 1 split window.
            # ----------------------------------------------------------------
            PHASE1_SPLIT_SECS = 8 * 60
            PHASE4_RESERVE = 240
            # Cap _run_protocol_model() timeout when Phase 3 is disabled: Phase 0
            # output is only needed until Phase 2 is submitted (8-min split), so
            # calls that start near or past that point skip immediately or use a
            # reduced timeout rather than running the full 300s.
            self._proto_deadline = (start_time + PHASE1_SPLIT_SECS) if not use_two_pass else None
            proto_executor = ThreadPoolExecutor(max_workers=2)
            proto_future_by_rel: dict[str, Future] = {}

            for fp in ranked_files:
                rel = str(fp.relative_to(source_dir))
                proto_future_by_rel[rel] = proto_executor.submit(self._run_protocol_model, source_dir, rel)

            # Release the executor (stop accepting new work) but let submitted
            # futures keep running in the background thread.
            proto_executor.shutdown(wait=False)

            def _get_proto_out(rel: str) -> dict:
                fut = proto_future_by_rel.get(rel)
                if fut is not None and fut.done():
                    try:
                        return fut.result()
                    except Exception:
                        pass
                return {}

            # ----------------------------------------------------------------
            # Phase 1: Tier 2 breadth — A1-A4 + B, all files, thinking ON.
            # Starts immediately (parallel with Phase 0 background worker).
            # Submitted file-major (all prompts for file1, then file2, ...).
            #
            # Submission order: small files first, large files last.
            # Large files (factory/governance, 12-18K input tokens, 350-430s/call)
            # occupy all 12 thread pool workers continuously; small peripheral
            # contracts (ContributionNft, ValidatorRegistry, AgentInference, 1-2K
            # tokens, 30-60s/call) placed at deep queue positions never execute
            # before the collection deadline when submitted after large files.
            # Putting small files first ensures they start in the first worker wave
            # and complete in 30-60s before large-file calls saturate the pool.
            # ----------------------------------------------------------------
            tier2_futures: list = []

            _phase1_order = sorted(ranked_files, key=lambda fp: fp.stat().st_size)

            for fp in _phase1_order:
                rel = str(fp.relative_to(source_dir))
                related = file_related[rel]

                for name, prompt in TOOL_LIST.items():
                    if name not in TIER2_PROMPT_NAMES:
                        continue

                    f = _submit_analyze(rel, related, name, prompt, tb=2048)

                    if f is None:
                        continue

                    tier2_futures.append(f)

            # ----------------------------------------------------------------
            # Phase 1 intermediate collection — let Phase 0 run in background.
            # Collect Phase 1 results for AT MOST PHASE1_SPLIT_SECS before
            # submitting Phase 2 (exits early if all tier2_futures finish first).
            # During this window Phase 0 serially classifies files; observed
            # ~45 s/file means roughly 8-10 files may have protocol context by
            # the time Phase 2 is submitted, though actual count is provider-dependent.
            # _collect() deduplicates via processed_scan_futures, so Phase 1
            # futures already collected here are safely skipped in the second
            # collection pass below.
            # ----------------------------------------------------------------
            phase1_split_deadline = start_time + PHASE1_SPLIT_SECS
            phase1_cutoff = scan_deadline - PHASE4_RESERVE

            try:
                remaining = max(1.0, phase1_split_deadline - time.time())

                for fut in as_completed(tier2_futures, timeout=remaining):
                    _collect(fut)

                    if time.time() >= phase1_split_deadline:
                        break
            except (TimeoutError, FuturesTimeoutError):
                pass

            # ----------------------------------------------------------------
            # Phase 2: Tier 3-4 depth — role-filtered per file, no thinking.
            # Submitted after Phase 1 split so _get_proto_out() returns real
            # Phase 0 results for files classified so far.
            # ----------------------------------------------------------------
            tier34_futures: list = []

            for fp in ranked_files:
                rel = str(fp.relative_to(source_dir))
                related = file_related[rel]
                proto_out = _get_proto_out(rel)
                pc = _fmt_protocol_context(proto_out)
                prompts_34 = self._select_prompts_for_file(rel, proto_out)

                for name, prompt in prompts_34:
                    f = _submit_analyze(rel, related, name, prompt, mdl=JSON_MODEL, pctx=pc)

                    if f is None:
                        continue

                    tier34_futures.append(f)

            # Phase 2 is now submitted.  If Phase 3 is disabled, Phase 0 results
            # are no longer needed — cancel queued futures to free the upstream slot.
            # If Phase 3 is enabled, keep Phase 0 running so later files still get
            # protocol context when Phase 3 snapshots _get_proto_out() at submission.
            if not use_two_pass:
                for _pf in proto_future_by_rel.values():
                    _pf.cancel()

            # Collect remaining Phase 1 + all Phase 2 until phase1_cutoff.
            # Phase 4 checks time_remaining directly; no gate on Phase 1/2 completion.
            scan_futures = tier2_futures + tier34_futures

            try:
                remaining = max(1.0, phase1_cutoff - time.time())

                for fut in as_completed(scan_futures, timeout=remaining):
                    _collect(fut)

                    if time.time() >= phase1_cutoff:
                        break
            except (TimeoutError, FuturesTimeoutError):
                pass

            # Sweep Phase 1/2 futures before Phase 4 starts:
            # - done: collect result now (no reason to defer)
            # - queued (not yet started): cancel() returns True → frees executor slots for Phase 4
            # - in-flight (running HTTP): cancel() returns False → cannot stop; track for deferred collection
            deferred_scan_futures: list = []
            for f in scan_futures:
                if f.done():
                    _collect(f)
                elif not f.cancel():
                    deferred_scan_futures.append(f)

            # ----------------------------------------------------------------
            # Phase 4: Agentic deep-dive on top-5 files (ROUTER_MODEL).
            # Runs BEFORE Phase 3 — requires ≥180 s remaining before scan_deadline.
            # Runs whenever time_remaining > 180 — not gated on Phase 1/2 completion.
            # The 4-minute reserve built into phase1_cutoff guarantees
            # time_remaining ≥ ~240 s here unless Phase 0 consumed most of the budget.
            # ----------------------------------------------------------------
            time_remaining = scan_deadline - time.time()

            if time_remaining > 180:
                top5 = ranked_files[:5]
                ag_mono_deadline = time.monotonic() + min(time_remaining, 5 * 60)

                # Pre-compute per-file lang_hint and protocol_context.
                # file_texts is already populated; _get_proto_out() returns Phase 0 results
                # that are complete by now (Phase 0 runs in parallel with Phase 1).
                _ag_file_ctx: dict[Path, tuple[str, str]] = {}
                for fp in top5:
                    rel = str(fp.relative_to(source_dir))
                    _content = file_texts.get(fp, "")
                    _lh = ""
                    if fp.suffix == '.rs':
                        _anc = ('anchor_lang' in _content or '#[program]' in _content or 'declare_id!' in _content)
                        _cw = not _anc and ('use cosmwasm_std' in _content or '#[entry_point]' in _content or 'use cw_storage_plus' in _content)
                        if _anc or _rs_flavor == "anchor":
                            _lh = ANCHOR_LANG_HINT
                        elif _cw or _rs_flavor == "cosmwasm":
                            _lh = GENERIC_LANG_HINT_BY_EXT[".rs_cosmwasm"]
                        else:
                            _lh = GENERIC_LANG_HINT_BY_EXT[".rs_generic"]
                    elif fp.suffix == '.cairo':
                        _lh = CAIRO_LANG_HINT
                    else:
                        _lh = GENERIC_LANG_HINT_BY_EXT.get(fp.suffix, "")
                    _pc = _fmt_protocol_context(_get_proto_out(rel))
                    _ag_file_ctx[fp] = (_lh, _pc)

                ag_executor = ThreadPoolExecutor(max_workers=len(top5))
                ag_futures = {
                    ag_executor.submit(
                        self._run_agentic_pass, source_dir,
                        str(fp.relative_to(source_dir)), ag_mono_deadline, f"ag-{i}",
                        *_ag_file_ctx[fp]
                    ): fp

                    for i, fp in enumerate(top5)
                }

                try:
                    ag_timeout = max(1.0, scan_deadline - time.time())

                    for fut in as_completed(ag_futures, timeout=ag_timeout):
                        try:
                            ag_vulns, ag_in, ag_out = fut.result(timeout=360)
                            all_vulnerabilities.extend(ag_vulns)
                            total_input_tokens += ag_in
                            total_output_tokens += ag_out
                        except Exception:
                            pass
                except (TimeoutError, FuturesTimeoutError):
                    for f in ag_futures:
                        f.cancel()
                finally:
                    ag_executor.shutdown(wait=False, cancel_futures=True)

            # Collect Phase 1/2 in-flight futures that were still running during Phase 4.
            # These were submitted before phase1_cutoff but could not be cancelled.
            # The Phase 4→5 gap (scan_deadline to verifier_deadline) is the collection window;
            # leave 90 s buffer so the verifier always gets a clean start.
            if deferred_scan_futures:
                _defer_window = max(1.0, verifier_deadline - time.time() - 90)
                try:
                    for fut in as_completed(deferred_scan_futures, timeout=_defer_window):
                        _collect(fut)
                except (TimeoutError, FuturesTimeoutError):
                    pass

            # ----------------------------------------------------------------
            # Phase 3: Two-pass at temperature=0.15 for recall diversity.
            # Runs only after Phase 4; requires ≥120 s so it is never the
            # reason Phase 4 was skipped.
            # ----------------------------------------------------------------
            if use_two_pass:
                time_remaining = scan_deadline - time.time()

                if time_remaining > 120:
                    pass2_futures: list = []

                    # File-major order so top-ranked files get second-pass coverage first.
                    # Per-file prompt selection reuses each file's real routing, including
                    # protocol-model skip lists and role-based filters from Phase 2.
                    for fp in ranked_files:
                        rel = str(fp.relative_to(source_dir))
                        related = file_related.get(rel, [])
                        proto_out = _get_proto_out(rel)
                        pc = _fmt_protocol_context(proto_out)

                        for name, prompt in TOOL_LIST.items():
                            if name not in TIER2_PROMPT_NAMES:
                                continue

                            f = _submit_analyze(rel, related, f"{name}_r2", prompt, mdl=PRIMARY_MODEL, tb=2048, temp=0.15, pctx=pc)

                            if f is None:
                                continue

                            pass2_futures.append(f)

                        for name, prompt in self._select_prompts_for_file(rel, proto_out):
                            f = _submit_analyze(rel, related, f"{name}_r2", prompt, mdl=JSON_MODEL, temp=0.15, pctx=pc)

                            if f is None:
                                continue

                            pass2_futures.append(f)

                    pass2_timed_out = False

                    try:
                        remaining = max(1.0, scan_deadline - time.time())

                        for fut in as_completed(pass2_futures, timeout=remaining):
                            _collect(fut)

                            if time.time() >= scan_deadline:
                                pass2_timed_out = True
                                break
                    except (TimeoutError, FuturesTimeoutError):
                        pass2_timed_out = True

                    if pass2_timed_out:
                        for f in pass2_futures:
                            f.cancel()

        finally:
            # Always shut down without waiting for in-flight LLM calls.
            # When the scan deadline hits, we want to return partial results
            # immediately rather than block on hung Chutes inference calls.
            executor.shutdown(wait=False, cancel_futures=True)

        files_analyzed = len(file_futures_done)

        # ----------------------------------------------------------------
        # Phase 5: Verifier soft rank.
        # Adjusts confidence; removes sub-0.40 findings before the expensive merge.
        # ----------------------------------------------------------------

        # Pre-cap per file before verifier so each per-file prompt stays within the
        # 500s inference budget.  Without this, files with 22+ prompts can produce
        # 80-100 raw findings, generating a ~10K-token prompt that can exceed the old 300s cap.
        # Keep the top-60 by (confidence DESC, rule_score DESC) as a safety net for extreme
        # outlier files (150+ findings); 60 findings × ~130s inference < 500s budget.
        _VERIFIER_PRE_CAP = 60
        if all_vulnerabilities:
            _pre_cap_by_file: dict = defaultdict(list)
            for _v in all_vulnerabilities:
                _pre_cap_by_file[_v.file].append(_v)
            all_vulnerabilities = []
            for _fvulns in _pre_cap_by_file.values():
                _fvulns.sort(key=lambda v: (-v.confidence, -rule_score(v)))
                all_vulnerabilities.extend(_fvulns[:_VERIFIER_PRE_CAP])
            print(f"[pre_verifier] capped to {len(all_vulnerabilities)} findings (max {_VERIFIER_PRE_CAP}/file)", flush=True)

        v_budget = verifier_deadline - time.time()
        if v_budget > 60 and all_vulnerabilities:
            ranked_file_strs = [str(fp.relative_to(source_dir)) for fp in ranked_files]
            all_vulnerabilities = self._run_verifier_soft_rank(
                all_vulnerabilities, source_dir, deadline=verifier_deadline,
                file_rank_order=ranked_file_strs,
            )

        # ----------------------------------------------------------------
        # Phase 6: Per-file cap → save raw → LLM merge → output cap.
        # ----------------------------------------------------------------
        max_findings_per_file = 50
        per_file: dict = defaultdict(list)

        for v in all_vulnerabilities:
            per_file[v.file].append(v)

        vulns: list = []
        for _fvulns in per_file.values():
            _fvulns.sort(key=lambda v: (-_SEV_ORDER.get(v.severity.value if v.severity else "low", 0), -rule_score(v)))
            vulns.extend(_fvulns[:max_findings_per_file])

        print(f"[pre_merge] raw={len(all_vulnerabilities)} -> per_file_cap={len(vulns)} (max {max_findings_per_file}/file)", flush=True)
        safe_proj = re.sub(r'[^A-Za-z0-9._-]+', '_', project_name).strip('_')

        try:
            raw_list = [
                {
                    "title":              v.title,
                    "description":        v.description,
                    "vulnerability_type": v.vulnerability_type,
                    "severity":           v.severity.value if v.severity else "high",
                    "confidence":         v.confidence,
                    "file":               v.file,
                    "location":           v.location,
                    "reported_by_model":  v.reported_by_model,
                    "root_cause":         getattr(v, "root_cause",        None),
                    "fix_location":       getattr(v, "fix_location",      None),
                    "violated_invariant": getattr(v, "violated_invariant", None),
                }
                for v in vulns
            ]

            with open(f"/tmp/raw_findings_{safe_proj}.json", "w") as rf:
                json.dump(raw_list, rf)
        except Exception:
            pass

        pre_merge_count = len(vulns)
        merge_start = time.time()
        _merge_budget = total_deadline - merge_start

        if _merge_budget >= 60:
            vulns = self.llm_merge_findings(vulns, model=JSON_MODEL, timeout=int(_merge_budget) - 5)
        else:
            print(f"[merge] Skipping LLM merge — only {_merge_budget:.0f}s remain in budget", flush=True)

        post_merge_count = len(vulns)
        merge_elapsed = time.time() - merge_start
        print(f"[merge] raw={pre_merge_count} -> post-merge={post_merge_count} (elapsed {merge_elapsed:.1f}s)", flush=True)

        vulns = roundrobin_select(vulns, max_output=100)
        total_found = len(vulns)
        print(f"[final] post-merge={post_merge_count} -> after-cap={total_found}", flush=True)

        return AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            total_vulnerabilities=total_found,
            vulnerabilities=vulns,
            token_usage={
                'input_tokens':  total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens':  total_input_tokens + total_output_tokens,
            },
        )

    def save_result(self, result: AnalysisResult, output_file: str = "agent_report.json"):
        """Serialise AnalysisResult to JSON at output_file and return the path."""

        result_dict = result.model_dump()

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2)

        return output_file

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def agent_main(project_dir: str = None, inference_api: str = None):
    """CLI entry point: initialise runner, call analyze_project, write the report, return result dict."""

    config = {'model': PRIMARY_MODEL}
    if not project_dir:
        project_dir = "/app/project_code"
    
    print(f"[INFO] agent_main START project={project_dir} api={inference_api} model={config['model']}")
    try:
        start_time = time.time()

        runner = BaselineRunner(config, inference_api)
        source_dir = Path(project_dir) if project_dir else None

        if not source_dir or not source_dir.exists() or not source_dir.is_dir():
            print(f"[ERROR] Invalid project directory: {project_dir}")
            sys.exit(1)

        result = runner.analyze_project(source_dir=source_dir,project_name=project_dir,)
        output_file = runner.save_result(result)
        end_time = time.time()
        elapsed = end_time - start_time

        print(f"[INFO] agent_main DONE vulns={result.total_vulnerabilities} files={result.files_analyzed} elapsed={elapsed:.1f}s report={output_file}")

        return result.model_dump(mode="json")
    except ValueError as e:
        print(f"[ERROR] agent_main ValueError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] agent_main Exception: {e}")
        sys.exit(1)

if __name__ == '__main__':
    import sys
    from pathlib import Path

    project_root = Path(__file__).parent.parent

    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from scripts.projects import fetch_projects
    from validator.manager import SandboxManager

    SandboxManager(is_local=True)
    time.sleep(10)
    fetch_projects()
    inference_api = 'http://localhost:8087'
    project = sys.argv[1] if len(sys.argv) > 1 else 'projects/code4rena_lambowin_2025_02'

    report = agent_main(project, inference_api=inference_api)
