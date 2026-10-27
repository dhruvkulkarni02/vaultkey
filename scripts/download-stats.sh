#!/usr/bin/env bash
# Print VaultKey download and traffic statistics as CSV rows:
#
#   date,repo,metric,key,value
#
# metric is "downloads" (key = release tag/asset name, value = cumulative
# download count) or one of clones, clones_unique, views, views_unique
# (key = "14d", value = total over GitHub's 14-day traffic window).
#
# Needs gh and jq. Release counts are public; the traffic metrics need a
# token with push access to both repositories (pass --no-traffic without one).
# Set STATS_DATE to override the date column (defaults to today, UTC).
set -euo pipefail

repos=(dhruvkulkarni02/vaultkey dhruvkulkarni02/homebrew-vaultkey)
date=${STATS_DATE:-$(date -u +%F)}
traffic=1
[[ ${1:-} == --no-traffic ]] && traffic=0

for repo in "${repos[@]}"; do
  gh api --paginate "repos/$repo/releases?per_page=100" --jq \
    ".[] | .tag_name as \$tag | .assets[]
     | [\"$date\", \"$repo\", \"downloads\", \"\(\$tag)/\(.name)\", .download_count]
     | map(tostring) | join(\",\")"

  if (( traffic )); then
    for kind in clones views; do
      gh api "repos/$repo/traffic/$kind" --jq \
        "\"$date,$repo,$kind,14d,\(.count)\", \"$date,$repo,${kind}_unique,14d,\(.uniques)\""
    done
  fi
done
