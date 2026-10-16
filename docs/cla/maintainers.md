# Accepting contributor agreements

Only the Project Owner identified in the agreement accepts a CLA. A maintainer may
check an existing acceptance record when reviewing a pull request. Repository
access alone does not make a person the recipient of CLA rights.

## Private acceptance record

Before confirming acceptance, check the complete signed agreement and retain it
with its email correspondence in private storage outside this repository. Record:

- Agreement version, source commit SHA and SHA-256 of the complete signed file.
- The Project Owner's account and numeric user ID from the signed agreement.
- Contributor's legal identity, email, GitHub account and numeric user ID, and how
  the account was associated with the signatory. Confirm that association through
  the contributor's GitHub account if the email alone does not establish it.
- Signature, signing date, verification method and private acceptance date.
- For a Corporate CLA, the signatory's authority and Schedule A employees. Keep
  subsequent authorization changes with the record. Each employee also needs an
  accepted Individual CLA.
- Related pull requests and the commit SHA reviewed when coverage was confirmed.

Do not accept an incomplete agreement, an agreement with altered terms without
review, or an unverified signature. If an agreement version or recipient changes,
review whether the existing acceptance covers the new contribution; do not silently
rewrite signed records or assume that signatures transfer to a different recipient.

## Before merging a pull request

Review commit authors and co-author trailers, not only the person who opened the
pull request. Confirm that each contributor has the required accepted agreements
and any employer authorization. Check third-party material and its license
separately; a CLA does not replace that check. Project Owner-authored changes do
not need a CLA granting rights back to that same owner.

Record that CLA coverage has been checked in the PR review, using GitHub account
names only. Keep legal names, addresses, signatures and signed documents private.
Recheck coverage when new commits or contributors are added, and record the new
head commit. Do not merge until coverage is confirmed for the current head.

A checked box in the PR template does not establish CLA acceptance. GitHub branch
rules should require a maintainer's approval and dismiss stale approvals on new
commits.
