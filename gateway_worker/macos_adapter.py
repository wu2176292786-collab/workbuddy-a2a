"""macOS Accessibility adapter contract, symmetric with the Windows adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .errors import AccessibilityPermissionError
from .windows_adapter import (
    FakeWindowsUIAutomationBackend,
    WindowsCommandJournal,
    WindowsCompatibilityProfile,
    WindowsDesktopAdapter,
)


@dataclass(frozen=True)
class MacOSCompatibilityProfile(WindowsCompatibilityProfile):
    def as_dict(self) -> dict[str, Any]:
        result = super().as_dict()
        result["platform"] = "macos"
        return result


class MacOSDesktopAdapter(WindowsDesktopAdapter):
    """Accessibility adapter using an injectable macOS backend seam."""

    permission_error_type = AccessibilityPermissionError
    permission_name = "macOS Accessibility"


class FakeMacOSAccessibilityBackend(FakeWindowsUIAutomationBackend):
    """Deterministic seam for macOS Accessibility contract tests."""

    def __init__(
        self,
        *,
        app_id: str,
        app_version: str,
        collaboration_conversation: str,
        controls: Iterable[str],
        reply: str = "",
        status: str = "completed",
        accessibility_permission_granted: bool = True,
    ) -> None:
        super().__init__(
            app_id=app_id,
            app_version=app_version,
            collaboration_conversation=collaboration_conversation,
            controls=controls,
            reply=reply,
            status=status,
            automation_permission_granted=False,
        )
        self.automation_permission_granted = None
        self.accessibility_permission_granted = accessibility_permission_granted


MacDesktopAdapter = MacOSDesktopAdapter
MacOSAccessibilityAdapter = MacOSDesktopAdapter
MacOSAccessibilityBackend = FakeMacOSAccessibilityBackend
MacOSCommandJournal = WindowsCommandJournal
