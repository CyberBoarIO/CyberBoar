#!/usr/bin/env bash
# Opens or reuses a main -> experimental/* PR after each push to main
# Review, conflict resolution and merging are left to maintainers
# GH_TOKEN is a GitHub App token so newly opened PRs start CI

set -euo pipefail

: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
repo=$GITHUB_REPOSITORY
owner=${repo%%/*}

main_sha=$(gh api "repos/$repo/git/ref/heads/main" --jq '.object.sha // empty')
[[ -n $main_sha ]] || { echo "no main branch" >&2; exit 1; }

branches=$(gh api "repos/$repo/git/matching-refs/heads/experimental/" --paginate |
  jq -r '.[] | select(.ref | startswith("refs/heads/experimental/")) |
    .ref | ltrimstr("refs/heads/")')

body='Bring the latest changes from `main` into this experimental branch.

Review the changes and CI results, resolve any conflicts, and merge with a
merge commit to preserve ancestry. This workflow does not merge pull requests.
Later commits to `main` automatically appear in this pull request.'

for branch in $branches; do
  encoded_branch=$(jq -rn --arg branch "$branch" '$branch | @uri')
  ahead=$(gh api "repos/$repo/compare/$encoded_branch...$main_sha" --jq .ahead_by)
  [[ $ahead =~ ^[0-9]+$ ]] || { echo "$branch: invalid comparison result" >&2; exit 1; }
  if [[ $ahead == 0 ]]; then
    echo "$branch: up to date with main"
    continue
  fi

  pr=$(gh api -X GET "repos/$repo/pulls" -f state=open \
    -f head="$owner:main" -f base="$branch" --jq '.[0].html_url // empty')
  if [[ -n $pr ]]; then
    echo "$branch: existing pull request $pr"
    continue
  fi

  pr=$(gh api -X POST "repos/$repo/pulls" -f head=main -f base="$branch" \
    -f title="Merge main into $branch" -f body="$body" --jq .html_url)
  echo "$branch: opened pull request $pr"
done
