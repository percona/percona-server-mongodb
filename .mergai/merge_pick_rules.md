# PSMDB merge-pick rules

## Target batch size

- Aim for **~50 commits per merge** (comfortable band ~30–65).
- Go smaller when there is a good reason to cut early; go larger only to reach a clean boundary, and
  never beyond the candidate window.
- Do not merge to the very newest candidate unless it is itself a clean boundary - leave the
  freshest few commits for the next batch (see "Stop short of unsettled commits" below).

## Where to cut

- **End on a self-contained commit, not a mid-stream one.** Large vendored third-party imports and
  auto-generated / regenerated artifact commits are ideal boundaries: they touch a well-isolated set
  of files, rarely depend on the commits right after them, and are easy to validate post-merge. When
  one sits near the target size, cut on it even if it is large - a big _atomic_ commit is a better
  boundary than a smaller commit in the middle of active churn.
- **Never split a coherent unit of work.** When consecutive commits clearly belong together - the
  same work item, a stacked series, or a change plus its follow-up/fixup - end the batch after the
  whole group or before it starts. Cutting between them lands the fork in a half-applied state that
  is hard to build, test, and conflict-resolve.
- **Keep a revert with what it reverts.** When upstream reverts a commit that is also in range,
  include the original and its revert in the **same batch** so they cancel out instead of importing
  a feature now and removing it next merge. If only the original is in range and its revert is just
  beyond the window edge, prefer stopping **before** the original so the next batch takes the pair
  together - importing a change upstream has already decided to undo is wasted conflict-resolution
  effort.
- **Stop short of unsettled commits.** This is why the batch should not end on the very newest
  candidate: the freshest commits are the ones most likely to be reverted or fixed up within a day
  or two. Leaving them for the next batch lets that churn resolve upstream first, so the fork
  imports the settled result rather than the back-and-forth.
