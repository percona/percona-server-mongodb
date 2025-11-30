#!/usr/bin/env python3
"""
Usage: check_format.py <base-commit>

This script checks for formatting issues in lines changed by the specified range of commits.
It compares the state of the code at the given base commit to the current HEAD,
and then checks for any formatting changes made by the code formatter after the last commit in HEAD.

(base) -----> (HEAD) -----> (working tree)
   ^             ^                 ^
   |             |                 |
 base commit   HEAD commit     after `bazel run format`
   |
   v
    specified as argument
"""

import sys
import difflib
from typing import List, Tuple, Dict, Iterable

from git import Repo, Commit

LineRange = Tuple[int, int]  # inclusive, 1-based line numbers: (start, end)


# Print error message and exit with code 2
def err(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(2)


# Return file contents at given commit as list of lines.
# If file does not exist at that commit, return empty list.
def read_blob_lines(commit, path: str) -> List[str]:
    try:
        blob = commit.tree / path
    except KeyError:
        return []
    data = blob.data_stream.read()
    return data.decode("utf-8", errors="ignore").splitlines()


# Return working-tree file contents as list of lines.
def read_worktree_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()


# convert to 1-based inclusive ranges
# x2 is correct as an inclusive upper bound when converting from half-open
def convert_indices(x1: int, x2: int) -> LineRange:
    """Convert 0-based half-open indices to 1-based inclusive line range."""
    start = x1 + 1
    end = x2
    return (start, end)


# Compute line ranges that changed between base and HEAD.
# We treat 'replace' and 'insert' as changed lines in HEAD.
# We don't care about base-side indices (i1, i2), only the HEAD-side (j1, j2).
# That is because we want to know which lines in HEAD were changed by commits range.
def get_changed_ranges_base_to_head(
    base_lines: List[str],
    head_lines: List[str],
) -> List[LineRange]:
    sm = difflib.SequenceMatcher(None, base_lines, head_lines)
    ranges: List[LineRange] = []
    for tag, _, _, j1, j2 in sm.get_opcodes():
        # consider only changes that add/modify lines in HEAD
        if tag in ("replace", "insert") and j1 != j2:
            ranges.append(convert_indices(j1, j2))

    return ranges


# Compute line ranges that changed between HEAD and working tree.
def get_changed_ranges_worktree_to_head(
    head_lines: List[str],
    wt_lines: List[str],
) -> List[LineRange]:

    ranges: List[LineRange] = []
    sm_hw = difflib.SequenceMatcher(None, head_lines, wt_lines)

    for tag, i1, i2, j1, j2 in sm_hw.get_opcodes():
        # Any non-equal opcode means HEAD vs WT differ in some way
        # However, we don't care about pure inserts in WT (they can't overlap HEAD changes).
        if tag not in ("replace", "delete"):
            continue

        ranges.append(convert_indices(i1, i2))

    return ranges


# Return True if two inclusive line ranges intersect.
def ranges_intersect(r1: LineRange, r2: LineRange) -> bool:
    a_start, a_end = r1
    b_start, b_end = r2
    return not (a_end < b_start or b_end < a_start)


# Return True if target range intersects with any of the ranges in the iterable.
def any_intersection_with(
    target: LineRange,
    ranges: Iterable[LineRange],
) -> bool:
    for r in ranges:
        if ranges_intersect(target, r):
            return True
    return False


# Return list of files that have unstaged changes and are also changed between base_ref and HEAD.
def get_candidate_files(
    repo: Repo, base_commit: Commit, head_commit: Commit
) -> List[str]:
    # Files with unstaged modifications (HEAD/index -> working tree)
    wt_diffs = repo.index.diff(None)
    wt_files = {d.a_path for d in wt_diffs if d.a_path is not None}

    if not wt_files:
        # No changes in working tree => no issues
        return []

    # Files changed between base and HEAD (PR diff)
    # NOTE:
    # - a_path is path in base_commit
    # - b_path is path in head_commit
    #
    # Depending on the change type we may have only one of them:
    # Change Type | a_path | b_path
    # ------------|---------|---------
    #   modify    | old.cpp | old.cpp
    #   add       | (none)  | new.cpp
    #   delete    | old.cpp | (none)
    #   rename    | old.cpp | new.cpp
    #
    # We want the path that exists in HEAD so our preference is b_path, then a_path.
    base_head_diffs = base_commit.diff(head_commit)
    base_head_files = {
        (d.b_path or d.a_path) for d in base_head_diffs if (d.b_path or d.a_path)
    }

    # Only care about files that:
    # - are changed in PR (base..HEAD)
    # - and have unstaged changes after formatter (HEAD..WT)
    return sorted(base_head_files & wt_files)


def main() -> int:
    if len(sys.argv) != 2:
        err(f"Usage: {sys.argv[0]} <base-commit>")

    base_ref = sys.argv[1]
    repo = Repo(".")

    base_commit = repo.commit(base_ref)
    head_commit = repo.head.commit

    candidate_files = get_candidate_files(repo, base_commit, head_commit)
    if not candidate_files:
        # No files modified in working tree that are also changed by specified commits
        return 0

    # Dict of path -> list of violated line ranges in working tree
    violations: Dict[str, List[LineRange]] = {}

    for path in candidate_files:
        base_lines = read_blob_lines(base_commit, path)
        head_lines = read_blob_lines(head_commit, path)
        wt_lines = read_worktree_lines(path)

        ranges_head = get_changed_ranges_base_to_head(base_lines, head_lines)
        if not ranges_head:
            # no HEAD lines we care about for this file
            continue

        ranges_wt = get_changed_ranges_worktree_to_head(head_lines, wt_lines)
        if not ranges_wt:
            # no WT changes vs HEAD for this file
            continue

        file_violations_ranges: List[LineRange] = []
        for range in ranges_wt:
            if any_intersection_with(range, ranges_head):
                file_violations_ranges.append(range)

        if file_violations_ranges:
            violations[path] = file_violations_ranges

    if not violations:
        # Formatter changes either:
        # - didn't touch lines changed in the provided commit range, or
        # - only touched files outside the provided commit range
        return 0

    # Emit GitHub annotations and fail.
    # GitHub annotation format:
    # ::error file=path,line=1,endLine=1::message
    msg = (
        "Formatting problems detected in lines changed by this PR. "
        "Run the formatter only on your changes or fix manual edits."
    )

    # Emit github annotations for each violating range
    for path, ranges in violations.items():
        for start, end in ranges:
            print(
                f"::error file={path},line={start},endLine={end}::{msg}",
                file=sys.stdout,  # annotations must go to stdout
            )

    return 1


if __name__ == "__main__":
    sys.exit(main())
