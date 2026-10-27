# Automate the WorkBuddy desktop App

The PoC targets the WorkBuddy desktop App on both Windows and macOS. Each Worker uses the platform's native accessibility automation first, with screenshot/OCR or clipboard techniques only as a fallback. The WorkBuddy login remains a human-managed local session; the Worker receives no WorkBuddy credentials.

## Consequences

The Worker needs a platform-specific Desktop adapter and a small compatibility matrix for supported WorkBuddy App versions. A UI automation spike must prove that the input control, conversation context, confirmation response, and completion result can be identified reliably on one Windows and one macOS machine before broader rollout.
