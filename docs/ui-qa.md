# UI QA — 2026-09-16

The admin console was exercised in a browser against an isolated, in-memory
control plane with a fictitious Windows endpoint. No production payment records
or PC settings were changed.

## Verified in the browser

- Desktop, 768 × 1024 tablet, and 390 × 844 phone layouts. No page-level
  horizontal overflow at the two responsive sizes; cards and forms stack.
- An invalid plan returns inline feedback without navigating away or losing input.
- A reminder queued after that error replaces the error with green success feedback.
- Creating a six-period plan displays the correct monthly dates and amounts.
- Marking the first fictitious installment paid replaces its row, retaining its
  amount and due date; reloading retains the paid state.
- Entering maintenance and enabling management update the policy target, action
  button, and command history. Reported agent state remains independent of the
  requested target until the endpoint checks in.
- Periodic health and command-panel replacements occur without losing the page.
- Unsupported firmware and Windows-account password controls remain disabled.

## Fixes prompted by QA

- Prevented the polling container's `hx-swap="none"` from suppressing child
  command success messages.
- Made the payment-plan form explicitly use HTMX, with inline rejection feedback
  and a page refresh after successful creation.
- Cleared stale error-container styling after a successful action.
- Preserved amount and due-date cells when an installment is marked paid.
- Added visible, associated payment-input labels, live feedback semantics,
  keyboard focus styles, and long endpoint-name wrapping.

The Rust backend/test-first skills guided HTTP regression coverage. All 89
workspace tests and Clippy with warnings denied passed on macOS.

## Remaining limits

The browser automation stalled on the native JavaScript confirmation dialog;
its cancellation and confirmation paths were not verified end-to-end. Keyboard
navigation also needs a manual browser check. The clear-restriction route and PIN
lifecycle have automated HTTP/agent coverage, but that is not a browser UI test.

The native Windows GUI cannot run on this Mac. Windows launch, rendering, service
integration, PIN entry, and payment-notice display still require a real Windows
PC/VM smoke test. A compiled release is not evidence of those runtime behaviors.

For repetition, use only disposable QA devices: reject an invalid plan, queue a
reminder, create a valid plan, mark a period paid, switch management modes, and
inspect the above viewport sizes. Test real PC restrictions only on an approved
test endpoint with administrator recovery available.
