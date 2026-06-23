"""Per-node up/down state machine (pure, I/O-free).

Reproduces the transition logic from the original ``syswatch.c`` ``monitor()`` (the block
that compares the new check ``result`` to ``this->lastcheck``). Kept free of I/O so it can be
exhaustively unit-tested.

Transition table (branch order matters — mirrors the C exactly):

1. ``result == NO_DNS``           -> record deathtime (on entry), lastcheck = NO_DNS. No page,
                                     downct untouched.
2. up (``result == 0`` and        -> if contacted: emit RECOVERY, set last_up, clear
   ``lastcheck != 0``)               contacted, downct = 0; else just clear (no page).
3. still down, same error         -> downct += 1; if downct >= max_down and not contacted:
   (``result == lastcheck != 0``)    emit DOWN.
4. down, error changed            -> downct = 1, lastcheck = result, deathtime = now;
   (``result != 0``,                 emit DOWN only if downct >= max_down and not contacted
   ``result != lastcheck``)          (i.e. only when max_down <= 1).

CRITICAL CONTRACT: this module never sets ``contacted`` to True — the notifier does that once
it has paged (the act of paging is the dedup point). The state machine only *emits* page
intents and reads ``not contacted`` as a guard. The recovery branch is the only place
``contacted`` is *cleared*. Likewise, whether a page is actually delivered (global
``--no-notify``, an empty contact address) is the notifier's concern, not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from psysmon.config.model import NodeState
from psysmon.status import Status, is_up


class PageIntent(Enum):
    """What the state machine wants the notifier to do after a check."""

    NONE = auto()
    DOWN = auto()
    RECOVERY = auto()


@dataclass(slots=True)
class Transition:
    """Outcome of applying a check result: the page intent and whether the display changed."""

    intent: PageIntent
    state_changed: bool


def apply_result(state: NodeState, result: int, now_wall: float) -> Transition:
    """Apply a check ``result`` to ``state`` in place and return the page intent.

    ``now_wall`` is wall-clock time (for the displayed outage/recovery timestamps). See the
    module docstring for the transition table and the ``contacted`` contract.
    """
    before = (state.lastcheck, state.downct, state.contacted, state.deathtime)
    intent = PageIntent.NONE

    if result == Status.NO_DNS:
        # DNS failure: record the outage but never page (the monitor's own resolver hiccup
        # shouldn't alarm). downct is left untouched, matching the original.
        if state.lastcheck != Status.NO_DNS:
            state.deathtime = now_wall
        state.lastcheck = Status.NO_DNS

    elif is_up(result):
        if not is_up(state.lastcheck):  # came up
            was_contacted = state.contacted
            state.lastcheck = Status.OK
            state.last_up = now_wall
            state.downct = 0
            if was_contacted:
                state.contacted = False
                intent = PageIntent.RECOVERY
        # else: still up — nothing changes.

    elif result == state.lastcheck:  # still down, same error
        state.downct += 1
        if state.downct >= state.max_down and not state.contacted:
            intent = PageIntent.DOWN

    else:  # down, error changed (includes up -> down, since lastcheck was OK)
        state.downct = 1
        state.lastcheck = result
        state.deathtime = now_wall
        if state.downct >= state.max_down and not state.contacted:
            intent = PageIntent.DOWN

    after = (state.lastcheck, state.downct, state.contacted, state.deathtime)
    return Transition(intent=intent, state_changed=before != after)


def maybe_repage(state: NodeState, now_mono: float, pageinterval_s: float) -> bool:
    """Return True if a contacted, still-down node is due for a re-page.

    Analog of the original ``periodic_page()``: re-page when ``now - lastcontacted >
    pageinterval`` (``pageinterval_s <= 0`` disables it). ``lastcontacted`` is a monotonic
    timestamp the notifier stamps when it pages. Re-paging is gated to *eligible*
    (non-suppressed) nodes by the scheduler — a fix vs. the C, which re-paged suppressed
    children.
    """
    if not state.contacted or pageinterval_s <= 0:
        return False
    return (now_mono - state.lastcontacted) > pageinterval_s
