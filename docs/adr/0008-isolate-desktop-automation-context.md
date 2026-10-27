# Isolate desktop automation in a supported WorkBuddy profile

The Worker operates a dedicated collaboration conversation or assistant entry in a pinned WorkBuddy desktop App version. Installation explicitly requests macOS Accessibility or Windows UI Automation permissions. If WorkBuddy is logged out, updated, blocked by a modal, or missing the expected entry, the Worker pauses and reports `NEEDS_ATTENTION`; it never automates login. Clipboard use is temporary and restored after the operation when it is required by the Desktop adapter.

## Consequences

The PoC needs a Windows and macOS compatibility profile and a setup wizard that verifies permissions and the collaboration conversation before enrollment completes.
