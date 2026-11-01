# Accepting contributor agreements

Only the Project Owner identified in the agreement accepts a CLA. A maintainer may
check an existing acceptance record when reviewing a pull request. Repository
access alone does not make a person the recipient of CLA rights.

## Individual CLA records

CLA assistant records each Individual CLA signature with the signer's GitHub
account, form details, date and the gist revision of the agreement. Export the
signature list as CSV regularly and keep the export in private storage outside
this repository. If the agreement changes, update this repository's
[Individual CLA](individual.md) and the gist together; signers are asked to sign
the new revision.

## Corporate CLA acceptance record

Before confirming acceptance, check the complete signed agreement and retain it
with its email correspondence in private storage outside this repository. Record:

- Agreement version, source commit SHA and SHA-256 of the complete signed file.
- The Project Owner's account and numeric user ID from the signed agreement.
- Signatory's legal identity, email, GitHub account and numeric user ID, and how
  the account was associated with the signatory. Confirm that association through
  the contributor's GitHub account if the email alone does not establish it.
- Signature, signing date, verification method and private acceptance date.
- The signatory's authority and Schedule A employees. Keep subsequent
  authorization changes with the record. Each employee also needs a signed
  Individual CLA.
- Related pull requests and the commit SHA reviewed when coverage was confirmed.

Do not accept an incomplete agreement, an agreement with altered terms without
review, or an unverified signature. If an agreement version or recipient changes,
review whether the existing acceptance covers the new contribution; do not silently
rewrite signed records or assume that signatures transfer to a different recipient.

## Before merging a pull request

The required `license/cla` check passes when every commit author has signed the
Individual CLA or is exempt. It does not read co-author trailers: confirm that each
co-author has signed too, and that any employer that owns the work has an accepted
Corporate CLA covering the contributor. Check third-party material and its license
separately; a CLA does not replace that check. Project Owner-authored changes do
not need a CLA granting rights back to that same owner.

When coverage needed a manual check, record it in the PR review, using GitHub
account names only. Keep legal names, addresses, signatures and signed documents private.
Recheck coverage when new commits or contributors are added, and record the new
head commit. Do not merge until coverage is confirmed for the current head.

A checked box in the PR template does not establish CLA acceptance. GitHub branch
rules should require a maintainer's approval and dismiss stale approvals on new
commits.
