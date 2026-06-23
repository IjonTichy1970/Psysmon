"""Per-node up/down state machine (pure, I/O-free).

Reproduces the transition logic from the original ``syswatch.c`` ``monitor()`` (the block
that compares the new check ``result`` to ``this->lastcheck``). Kept free of I/O so it can be
exhaustively unit-tested.

Transition table (branch order matters — mirrors the C exactly):

1. ``result == NO_DNS``           -> set deathtime, lastcheck = NO_DNS. No page.
2. up (``result == 0`` and        -> if contacted: emit RECOVERY, set last_up, clear
   ``lastcheck != 0``)               contacted, downct = 0; else just clear (no page).
3. still down, same error         -> downct += 1; if downct >= max_down and not contacted:
   (``result == lastcheck != 0``)    emit DOWN.
4. down, error changed            -> downct = 1, lastcheck = result, deathtime = now;
   (``result != 0``,                 emit DOWN only if downct >= max_down and not contacted
   ``result != lastcheck``)          (i.e. only when max_down <= 1).

CRITICAL CONTRACT: this module only *emits* page intents and reads ``not contacted`` as a
guard. It never sets ``contacted`` — the notifier does that after sending (or immediately
when a node has no contact address). The recovery branch is the only place ``contacted`` is
cleared.

Milestone 4 — not yet implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from sysmon.config.model import NodeState


class PageIntent(Enum):
    """What the state machine wants the notifier to do after a check."""

    NONE = auto()
    DOWN = auto()
    RECOVERY = auto()


@dataclass(slots=True)
class Transition:
    """Outcome of applying a check result: the page intent and whether display changed."""

    intent: PageIntent
    state_changed: bool


def apply_result(
    state: NodeState, result: int, now_wall: float, notify_enabled: bool
) -> Transition:
    """Apply a check ``result`` to ``state`` in place and return the page intent.

    See the module docstring for the transition table and the ``contacted`` contract.
    """
    raise NotImplementedError("Milestone 4: state machine")


def maybe_repage(state: NodeState, now_mono: float, pageinterval_s: float) -> bool:
    """Return True if a contacted, still-down node is due for a re-page.

    Analog of the original ``periodic_page()``: re-page when
    ``now - lastcontacted > pageinterval``. Re-paging is gated to *eligible* (non-suppressed)
    nodes by the scheduler (a fix vs. the C, which re-paged suppressed children).
    """
    raise NotImplementedError("Milestone 4: re-page timer")
