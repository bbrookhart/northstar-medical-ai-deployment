from __future__ import annotations

import hashlib
import json

from polaris.domain import FollowUpAction


def action_digest(action: FollowUpAction) -> str:
    """The canonical digest an approval is bound to.

    This lives outside the action service because both the service and the trusted approval preview
    must compute it identically. A preview that derived the digest any other way could show an
    approver one action while the decision bound another.
    """

    canonical = json.dumps(
        action.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()
