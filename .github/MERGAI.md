# Mergai Workflow

The `mergai.yml` workflow automates the process of merging upstream MongoDB commits into Percona Server for MongoDB, including AI-assisted conflict resolution and AI-assisted summary of merged commits.

## Quick Start

1. **Check available commits**: Visit the [Fork Status page](https://percona.github.io/percona-server-mongodb/)
2. **Trigger merge**: Go to Actions → "mergai bot" → "Run workflow", or use CLI:

   ```bash
   gh workflow run .github/workflows/mergai.yml -f merge-pick=<SHA>
   ```

3. **Review the PR**: The workflow creates one of two PR types:
   - **Merge PR** - Clean merge without conflicts, ready for review
   - **Conflict Solution PR** - Contains conflict markers with AI-resolved solutions visible in the diff for easy review
4. **Build and test**: Check out the branch locally, build, and run tests
5. **Merge**: Post `/fast-forward` comment to merge without double commits

## Workflow Jobs

| Job               | Trigger                          | Purpose                                              |
| ----------------- | -------------------------------- | ---------------------------------------------------- |
| `trigger-merge`   | Manual dispatch                  | Performs merge, handles conflicts with AI resolution |
| `solution-merged` | PR merged to `mergai/*/conflict` | Finalizes after solution PR is merged                |

## Understanding PRs

### Merge PR (no conflicts)

- Direct PR to main branch
- Review "Auto-merged files" section

### Conflict Resolution PR

- PR from `solution` branch into `conflict` branch
- Check "Conflict Context" and "Solutions" sections for AI-resolved conflicts
- Unresolved files will have conflict markers visible in review

## Making Fixes

If tests fail or changes are needed:

### Option 1 - Simple (commits not tracked by mergai)

Add commits directly to the branch. This works but commits won't be marked as solutions for future reuse.

### Option 2 - Tracked (recommended)

```bash
# Add your commits, then:
mergai commit sync       # Add mergai notes to commits
mergai branch push main  # Push branch
mergai notes push        # Push notes
mergai pr update main    # Update PR description
```

**Optional**: Use `mergai commit squash` to squash all commits into the merge commit.

## Merging the PR

Ensure the PR branch is rebased onto (and fast-forwardable to) the base branch, then post a comment with `/fast-forward` to merge without creating extra merge commits.

## Canceling a Merge

To cancel an in-progress merge:

1. Close the PR
2. Delete the associated branch(es)

## Local Setup (Optional)

For local work with mergai:

```bash
mergai config           # One-time: configure git for note markers and diff3
mergai notes update     # Sync notes from remote
mergai context init     # Create local context from commit notes
# Now other mergai commands work
```

If you need to rebase an existing merge:

```bash
mergai context init
mergai rebase
```

## Resources

- [Mergai Documentation](https://github.com/Percona-Lab/mergai#readme)
- [Fork Status Dashboard](https://percona.github.io/percona-server-mongodb/)
