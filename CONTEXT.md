# Cross-user Agent Collaboration

This context defines the shared language for routing tasks between separate users' WorkBuddy assistants through a cloud gateway and local automation workers.

## Participants

**User**:
The human owner who interacts with an assistant through WeChat and ClawBot.
_Avoid_: operator, account

**Agent**:
The user's WorkBuddy assistant identity that can send and receive delegated tasks.
_Avoid_: bot, worker

**Worker**:
A trusted, device-bound program running on the user's computer that connects to the gateway and operates the local WorkBuddy UI.
_Avoid_: agent, client bot

**Gateway**:
The cloud service that authenticates Workers, routes task messages between Agents, enforces the Agent allowlist, and records task audit events.
_Avoid_: relay bot, shared WorkBuddy

**Task**:
A bounded unit of work delegated from one Agent to another, including its required inputs, authorization state, progress messages, and result summary.
_Avoid_: chat, conversation

**WorkBuddy session**:
The already-authenticated local WorkBuddy application state controlled by a Worker. It is separate from the Worker's Gateway connection.
_Avoid_: cloud session, Agent login

**WorkBuddy interface**:
The visible WorkBuddy desktop App window through which the local assistant receives prompts and displays replies; it is the surface automated by a Worker when no suitable WorkBuddy API exists in this PoC.
_Avoid_: ClawBot UI, WeChat UI, Gateway UI

**Desktop adapter**:
The platform-specific Worker component that controls the WorkBuddy desktop App using Windows UI Automation or macOS Accessibility APIs.
_Avoid_: browser adapter, ClawBot adapter

**Collaboration conversation**:
The dedicated WorkBuddy conversation or assistant entry used by the Worker for delegated Tasks, separate from the user's ordinary conversations.
_Avoid_: default chat, shared chat

**Compatibility profile**:
The supported WorkBuddy App version and platform combination for which a Desktop adapter's selectors and state checks have been verified.
_Avoid_: app version alone, OS support

**Automation permission**:
The operating-system grant that allows a Worker to inspect and control the WorkBuddy desktop App.
_Avoid_: WorkBuddy login permission, Gateway permission

**Admin console**:
The restricted Gateway interface used to manage Team membership, Agent allowlists, Worker pairing, Task templates, and audit visibility.
_Avoid_: database console, WorkBuddy admin

**Device revocation**:
The administrative action that invalidates a Worker's key and sessions and prevents it from receiving new Tasks.
_Avoid_: account deletion, Agent deletion

**Task hash**:
An immutable digest over the canonical sender, recipient, template version, input, scope, permissions, and expiry that binds approval to the exact Task contents.
_Avoid_: message hash, prompt checksum

**Confirmation nonce**:
A single-use value that binds one recipient approval to one Task hash and prevents confirmation replay.
_Avoid_: task ID, session token

**Worker epoch**:
A monotonically increasing generation assigned when an Agent's Worker is paired or replaced; older generations cannot change Task state.
_Avoid_: app version, connection ID

**Fencing token**:
A lease-bound capability checked on every Worker event so a superseded or revoked Worker cannot continue controlling a Task.
_Avoid_: access token, heartbeat

**Execution evidence**:
Machine-checkable proof defined by a Task template that supports completion, such as a matching command identifier, valid output schema, and consistent result hash.
_Avoid_: Agent completion claim, success text

**Result egress policy**:
The rule that determines which fields or outputs may leave the receiving Agent's isolated execution boundary and whether recipient approval is required.
_Avoid_: notification preference, output formatting

**Delegation**:
The act of an Agent asking another Agent to perform a Task under an explicit scope and confirmation policy.
_Avoid_: notification, handoff

**Pairing**:
The one-time process that binds a Worker device to an approved Agent using a short-lived code and administrator approval.
_Avoid_: login, WorkBuddy sign-in

**Active Worker**:
The single Worker permitted to operate an Agent during the PoC.
_Avoid_: primary bot, session owner

**Confirmation envelope**:
A machine-readable response that identifies a Task and records the recipient's accept or reject decision.
_Avoid_: acknowledgement text, thumbs-up

**Task expiry**:
The deadline after which an undelivered or unaccepted Task is no longer valid.
_Avoid_: retry limit, session timeout

**Task artifact**:
A file or external output produced by a Task and referenced separately from its text result summary.
_Avoid_: attachment, transcript

**Cooperative cancellation**:
A cancellation request that a Worker delivers to an active Task and reports separately from the eventual stop state.
_Avoid_: forced stop, kill

**Team**:
The administrator-managed group of Users and their approved Agents that may exchange Tasks.
_Avoid_: tenant, chat group

**Task template**:
An administrator-approved description of a supported Task type, including required inputs, output shape, and confirmation rules.
_Avoid_: prompt preset, workflow script

**Audit event**:
A time-stamped record of a Task or Worker lifecycle change containing metadata and outcome information without a full conversation transcript.
_Avoid_: chat log, telemetry dump

**Protocol version**:
The version identifier on a Gateway-Worker message envelope used to reject incompatible messages explicitly.
_Avoid_: app version, WorkBuddy version

**Worker connection**:
The authenticated outbound WSS session from a Worker to the Gateway that carries Task events and heartbeats.
_Avoid_: Agent-to-Agent connection, WorkBuddy connection

**Task event**:
An append-only state or message transition associated with a Task and identified for idempotent delivery.
_Avoid_: webhook, chat message

**Needs input**:
A Task state in which the receiving Agent has asked for information within the existing authorization scope before it can continue.
_Avoid_: blocked, new task

**Needs attention**:
A Task or Worker state requiring a person because UI state, completion, cancellation, or authorization cannot be established safely.
_Avoid_: failed, retrying

**Safe stop point**:
A point at which a Worker can stop a running Task without knowingly leaving a partial external action.
_Avoid_: immediate kill, forced cancellation
