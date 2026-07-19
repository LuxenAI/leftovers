"""Cooperative signal cancellation for the portable command entry point."""

from __future__ import annotations

import signal
from collections.abc import Callable

_pending_signal: signal.Signals | None = None


def install_cancellation_handlers() -> Callable[[], None]:
    """Defer termination until a child-owning operation reaches safe cleanup.

    Raising directly from a signal handler can interrupt ``Popen`` after its
    child exists but before the caller has registered it for process-group
    cleanup. The runner checks this recorded state only after registration.
    """

    global _pending_signal
    _pending_signal = None
    previous: dict[signal.Signals, signal.Handlers] = {}

    def cancel(received: int, _frame: object) -> None:
        global _pending_signal
        _pending_signal = signal.Signals(received)

    for received in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[received] = signal.getsignal(received)
        signal.signal(received, cancel)

    def restore() -> None:
        global _pending_signal
        for received, handler in previous.items():
            signal.signal(received, handler)
        _pending_signal = None

    return restore


def raise_if_cancelled() -> None:
    """Raise after the active child has been registered for cleanup."""

    global _pending_signal
    received = _pending_signal
    if received is not None:
        _pending_signal = None
        raise KeyboardInterrupt(f"Leftovers received {received.name}")
