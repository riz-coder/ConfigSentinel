# Corrective action workflow

An independent auditor rejection or request for updated evidence creates one
draft corrective action linked to that immutable assessment. Preliminary AI
findings do not create remediation obligations.

For assessments recorded before this package was installed, an authorized user
can select **Generate missing gap drafts** once. It only creates a draft where
the auditor decision is reject/request-update and no action already exists.

The tenant owner or compliance lead assigns an ISP-side owner, due date and
remediation plan. The assignee adds progress and new encrypted evidence versions
against the same clause, then submits the action for retest. Only an auditor can
close a retest-ready action or reopen it with a recorded reason.

`CLOSED` means the corrective-action retest workflow was closed; it never turns
`SOURCE_PENDING` into verified law, and it does not represent regulator
certification. History and evidence-version links are append-only.
