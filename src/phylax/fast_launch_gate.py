"""Dispatch-boundary gate for the direct-xAI fast-mode operator exception.

The policy helpers in the model-governance packages refuse ``fast=True`` because
metadata cannot prove an operator decision.  The exception is enforced here, by
the trusted dispatcher, immediately before provider invocation: it consumes one
fresh P5 receipt that an independent human-evidence verifier produced for the
exact launch about to run.  Nothing in this module creates approval authority,
reads configuration, an environment value, or an agent-writable file, or calls a
provider.
"""

from __future__ import annotations

from collections.abc import Mapping

from .model_launch_approval import ModelLaunchApprovalAuthority, ModelLaunchIntent
from .p5_approval import P5ApprovalDecision, P5ApprovalReceipt


class FastLaunchRefused(ValueError):
    """Raised when the fast-mode exception is not backed by a valid one-use approval."""


def authorize_direct_xai_fast(
    authority: ModelLaunchApprovalAuthority,
    receipt: P5ApprovalReceipt,
    *,
    launch: Mapping[str, object],
    operator_principal: str,
    caller_principal: str,
) -> P5ApprovalDecision:
    """Spend one receipt for the exact fast launch, or refuse without side effects.

    ``launch`` must be the dispatcher's own canonical launch fields, never a
    caller-supplied intent: the intent is rebuilt here, so the receipt's signed
    digest binds model, normalized effort, fast flag, scope, expiry and request
    identity.  A mismatch is detected before the receipt is spent; expiry,
    duplicate use and tampering are refused by the native P5 consume.
    """
    if caller_principal != operator_principal:
        raise FastLaunchRefused("fast mode may only be spent by the approving operator principal")
    try:
        intent = ModelLaunchIntent.from_fast_launch(operator_principal, dict(launch))
        return authority.consume(receipt, intent)
    except ValueError as exc:
        raise FastLaunchRefused(f"direct-xAI fast mode refused: {exc}") from exc
