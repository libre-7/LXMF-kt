# LXMF-kt — Documented Deviations from the Python Reference

This file is the **single source of truth** for every place where LXMF-kt's logic intentionally diverges from `markqvist/LXMF`. Any divergence not listed here is a bug, not a deviation.

## Rule

> All logic in LXMF-kt MUST mirror the python reference identically. Deviations are allowed ONLY for one of two reasons, both of which MUST be documented here before the code lands.

**Allowed reason 1 — Language/runtime forced.** The python pattern cannot be expressed faithfully in kotlin or on the JVM. Examples: coroutines vs threads, `@Volatile` vs the GIL, `ReentrantLock` where python relies on GIL-implicit serialization, `kotlinx.coroutines.runBlocking` boundaries at JVM/non-coroutine seams.

**Allowed reason 2 — New feature not present in python.** Kotlin-only API surface added for downstream consumers (Android lifecycle adapters, mobile-specific entry points, etc.). The kotlin-only behavior must not change semantics of any code path that *does* exist in python.

## Process

1. Before changing a kotlin port file in a way that diverges from the python reference, read the corresponding python source.
2. If the divergence is unavoidable for one of the two reasons above, add a section below using the template, then implement the change.
3. If you're unsure whether a divergence is justified, ask the human owner before picking unilaterally. Ports drift one small "harmless" choice at a time.
4. Reviewers should reject any PR that introduces a kotlin/python semantics divergence not represented in this file.

## Entry template

```markdown
### <short title> — <kotlin-file-relative-path>:<line-or-symbol>

**Python reference:** `<path>:<line>` (e.g. `LXMF/LXMRouter.py:2554-2580`)

**Category:** language/runtime forced  |  new feature

**Date:** YYYY-MM-DD

**Tracking:** issue/PR link, if any.

**Description:** what the kotlin code does, why it differs from python, and (for category 1) why no kotlin idiom can express the python semantics directly.

**Re-evaluation:** if a future kotlin/JVM/library change would make the python pattern expressible, what to look for.
```

---

## Deviations

### `@Volatile` on `LXMessage.progress` — `lxmf-core/src/main/kotlin/network/reticulum/lxmf/LXMessage.kt:142`

**Python reference:** `LXMF/LXMF/LXMessage.py:156` (`self.progress = 0.0`), with cross-thread writers at `LXMessage.py:474, 488, 496, 506, 512, 559, 571, 583, 618` (the `__update_transfer_progress` callback path) and reads from any caller polling for UI progress display.

**Category:** language/runtime forced

**Date:** 2026-05-12

**Tracking:** torlando-tech/LXMF-kt#34 (greptile review of `cmdLxmfGetMessageProgress`)

**Description:** Python's GIL serialises attribute reads/writes — `self.progress = X` from a Resource progress callback thread is implicitly visible to a main-thread poller without any explicit synchronisation. On the JVM, `var progress: Double = 0.0` has neither visibility nor atomicity guarantees: JLS §17.7 explicitly permits non-volatile `double` (and `long`) reads to **tear** (be observed as 32-bit halves of two different writes), and there is no happens-before edge between a write on one thread and a read on another without a synchronisation action. HotSpot makes 64-bit reads atomic in practice on modern hardware, but ART (Android Runtime) does not guarantee this, and visibility (vs atomicity) is implementation-defined either way. `@Volatile` is the direct JVM idiom for "what Python's GIL gives you for free": each read sees the latest committed write, and 64-bit access is guaranteed atomic.

Writers in this port: `LXMRouter.processOpportunisticDelivery` (LXMRouter.kt:739, 755) — `processingScope` coroutine; `LXMRouter.sendViaPropagation` Resource progressCallback (LXMRouter.kt:1258) — Resource background thread; `LXMRouter.sendViaLink` Resource progressCallback + completion callback (LXMRouter.kt:1335, 1340) — Resource background thread.

Readers: any consumer polling progress for UI display, plus `:conformance-bridge`'s `cmdLxmfGetMessageProgress` (Main.kt:740), which is what surfaced this issue in code review.

**Re-evaluation:** Remove `@Volatile` only if `LXMessage` ever migrates to an immutable / coroutine-`StateFlow`-backed progress representation, or if Kotlin gains a portable concurrency annotation that subsumes JVM-`@Volatile` semantics across all targets (Native, JS) the lib might one day support.

### DIRECT-link CLOSED-branch path re-request relocated to the link `closedCallback` — `lxmf-core/src/main/kotlin/network/reticulum/lxmf/LXMRouter.kt::establishLinkForMessage` (closedCallback) and `::processDirectDelivery` (CLOSED branch)

**Python reference:** `LXMF/LXMF/LXMRouter.py:2610-2629` — inside `process_outbound`'s per-message loop, when a message's DIRECT delivery link is `CLOSED`, Python re-requests the path (`RNS.Transport.request_path`), distinguishing "was active, closed unexpectedly" (`direct_link.activated_at != None`) from "never activated" (re-request once, guarded by the dynamic `path_request_retried` attribute), then pops both `direct_links` and `backchannel_links` and reschedules.

**Category:** language/runtime forced

**Date:** 2026-06-10

**Tracking:** columba#1004 (D2). See also `columba` memory `issue-1004-path-requests-direct-delivery`.

**Description:** Python's `direct_links` retains a CLOSED link until the next `process_outbound` tick observes it and runs the per-message CLOSED branch. The kotlin port is event-driven: `establishLinkForMessage` creates the `RNS.Link` with a `closedCallback` that fires the instant the link closes (Link watchdog establishment-timeout or unexpected teardown) and **eagerly removes** the link from `directLinks`, then calls `triggerProcessing()`. Consequently a CLOSED link is essentially never observed by `processDirectDelivery` — the next tick lands in the no-link branch — so porting Python's re-request into that branch would be dead code.

The re-request is therefore relocated to the `closedCallback`, where kotlin actually handles link close. It replicates Python's logic faithfully: `closedLink.activatedAt > 0` ⇒ re-request (was active); else re-request once gated by `LXMessage.pathRequestRetried` (never activated). It is additionally gated on the initiating message still needing delivery (`state == OUTBOUND || SENDING`) to reproduce the fact that Python's CLOSED branch only runs for a message still in the outbound loop — without this, a normal post-delivery close would emit a spurious path request that Python never makes. `processDirectDelivery`'s CLOSED branch is retained as a no-op-ish safety net (clear both link maps + reschedule) for the close-callback race window, but performs no re-request to avoid double-firing.

This matters specifically for transport-enabled nodes: reticulum-kt's `Transport.deregisterLink` stale-path recovery (expire + re-request on pending-link timeout) is intentionally gated to non-transport nodes (Python `Transport.py:504` parity), so for transport-mode users the LXMF close-time re-request is the only mechanism that refreshes a stale path after a failed DIRECT link.

**Re-evaluation:** If the kotlin `LXMRouter` ever stops eagerly removing the link in `closedCallback` and instead lets `processDirectDelivery` observe and pop CLOSED links (matching Python's `direct_links` lifecycle), move the re-request back into the CLOSED branch and delete this deviation. The per-message `pathRequestRetried` semantics would then align 1:1 with Python without the close-event approximation.

### `LXMessage.send()` delegates to an LXMRouter-owned hook — `lxmf-core/src/main/kotlin/network/reticulum/lxmf/LXMessage.kt::send`

**Python reference:** `LXMF/LXMF/LXMessage.py:463-508` — `send()` synthesises `RNS.Packet`/`RNS.Resource` objects directly from inside the message class (`__as_packet`, `__as_resource`) and drives state transitions (`SENDING`/`SENT`, progress 0.10/0.50, delivery/timeout callbacks) itself.

**Category:** architecture (port-forced)

**Date:** 2026-08-23

**Description:** In this port all packet/resource synthesis and lifecycle wiring lives in `LXMRouter` (`sendViaLink`, opportunistic path, `sendViaPropagation`); `LXMessage.send()` performs Python's pre-send annotations (`determine_transport_encryption()` + `determine_compression_support()`, both ported verbatim including the OPPORTUNISTIC/DIRECT/PROPAGATED/PAPER × SINGLE/GROUP matrix) and then delegates actual transmission to a router-registered hook. Without a registered hook the message is marked `FAILED` and `failed_callback` fires — Python would instead raise on a null `__delivery_destination` inside `__as_packet`. The delegation keeps one owner for link teardown/retry semantics that this port's event-driven router already implements (see the DIRECT-link CLOSED-branch deviation below), avoiding two competing send paths.

**Re-evaluation:** If the router ever grows a pass-through registration API where callers wire raw RNS destinations per-message, `send()` could synthesise packets directly again; revisit only if a use-case appears that needs message-class-level sending without any router.

### `set_destination` / `set_source` are validation-only — `lxmf-core/src/main/kotlin/network/reticulum/lxmf/LXMessage.kt::setDestination` / `::setSource`

**Python reference:** `LXMF/LXMF/LXMessage.py:235-242` and `255-262` — name-mangled private fields rebindable once; later assignment raises.

**Category:** language-forced

**Date:** 2026-08-23

**Description:** This port declares `destination`/`source` as immutable constructor properties (`val`), which every existing call site (router, tests, bridge) already relies on. `setDestination`/`setSource` therefore replicate Python's *contract* — reject non-SINGLE destinations, reject reassignment with the same exception types/messages — but cannot rebind the property when it is still null on an outbound message constructed via `create()` (where both are always supplied anyway). For receive-side messages (`unpackFromBytes`) the properties are null and validation-only semantics are observable: a null/non-SINGLE argument throws `IllegalArgumentException`, a second valid call throws `IllegalStateException`.

**Re-evaluation:** If Kotlin-side code ever needs late destination binding (e.g. deferred resolution of an incoming sender into a `Destination` object), migrate the backing storage to `private var` + public `val` accessors and let these setters perform the actual rebind, deleting this deviation.

### `as_qr()` returns the URI payload contract, not a rendered image — `lxmf-core/src/main/kotlin/network/reticulum/lxmf/LXMessage.kt::asQr`

**Python reference:** `LXMF/LXMF/LXMessage.py:718-744` — renders via the optional `qrcode` module and returns a PIL image; returns None (with critical log) when the module is missing.

**Category:** dependency-forced

**Date:** 2026-08-23

**Description:** The JVM core deliberately does not bundle a QR renderer or an image type. `asQr()` mirrors Python's missing-dependency branch: it validates paper packing (throwing `IllegalStateException` on non-paper messages exactly like Python's `TypeError`) and returns null after logging that a renderer is required, directing callers to use `asUri()` output as the QR payload. Android/app consumers attach their own ZXing-based renderer; keeping the image type out of `-core` avoids pinning java.awt/pixel classes into an Android-consumable artifact.

**Re-evaluation:** If a JVM-wide standard QR type becomes available in the dependency tree (e.g. a multiplatform qrcode artifact), add an optional `zxing`/`qrcode-multiformat` scoped dependency and return a real image behind a separate `asQrImage()` while keeping this method as the payload accessor.
