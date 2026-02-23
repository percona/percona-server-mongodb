## Project Invariants

The PSMDB is a fork of MongoDB, and it is essential to maintain compatibility with MongoDB's features and APIs while integrating Percona's enhancements.

When resolving merge conflicts, adhere to the following guidelines:

- Check "Conflict Hints" section below for specific files that may have conflicts and how to handle them.
- Don't remove or alter any Percona-specific features, enhancements, or bug fixes.
- Prioritize Percona's changes over MongoDB's when conflicts arise, however, make sure only relevant Percona's changes are kept. Any surrounding code that is not related to Percona's changes can be changed to match MongoDB's version.
- Do not restrict the conflict resolution to only the lines marked by the conflict markers. Consider the surrounding code context to ensure a coherent and functional final version. Do not resolve conflict only by choosing appropriate block. Instead, try to merge the changes from both sides when possible.
- Do not make any unrelated changes to the code.
- ALWAYS make sure the conflict markers are COMPLETELY removed (<<<<<<<, =======, >>>>>>>, and |||||||) from the final code.

## Conflict Hints

### MODULE.bazel.lock

**⚠️ IMPORTANT: Resolve this file LAST, after all other conflicts are resolved.**

**Action:**

1. First, resolve ALL other conflicting files
2. Then, remove ALL conflict markers from `MODULE.bazel.lock` by accepting EITHER "ours" OR "theirs" version entirely
3. Finally, **EXECUTE** the command: `bazel query //... >/dev/null` to regenerate the file

**Reason:** This lock file cannot be manually merged. The conflict markers must be removed first so bazel can run, then the command regenerates the file correctly.
**Do NOT:** Attempt to manually merge the conflicting content.
