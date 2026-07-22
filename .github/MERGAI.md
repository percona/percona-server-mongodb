# Mergai Workflow

The `mergai.yml` workflow automates the process of merging upstream MongoDB commits into Percona
Server for MongoDB, including AI-assisted conflict resolution and AI-assisted summary of merged
commits.

A companion `periodic-merge.yml` workflow runs the merge loop unattended: on a daily schedule (and,
optionally, right after each merge lands) it decides _whether_ to merge and, if so, dispatches
`mergai.yml` to do the work — replacing a human watching the Fork Status page and triggering merges
by hand. Both workflows are tuned through GitHub Actions
[repository variables](#repository-variables) and the merge-gate settings in `.mergai/config.yml`.

## Quick Start

1. **Check available commits**: Visit the
   [Fork Status page](https://percona.github.io/percona-server-mongodb/)
2. **Trigger merge**: Go to Actions → "mergai bot" → "Run workflow", or use CLI:

   ```bash
   gh workflow run .github/workflows/mergai.yml -f merge-pick=<SHA>
   ```

3. **Review the PR**: The workflow creates one of two PR types:
   - **Merge PR** - Clean merge without conflicts, ready for review
   - **Conflict Solution PR** - Contains conflict markers with AI-resolved solutions visible in the
     diff for easy review
4. **Build and test**: Check out the branch locally, build, and run tests
5. **Merge**: Post `/fast-forward` comment to merge without double commits

## Workflows

### `mergai.yml` ("mergai bot")

| Job               | Trigger                          | Purpose                                                                  |
| ----------------- | -------------------------------- | ------------------------------------------------------------------------ |
| `trigger-merge`   | Manual dispatch                  | Picks a commit, performs the merge, handles conflicts with AI resolution |
| `solution-merged` | PR merged to `mergai/*/conflict` | Finalizes after solution PR is merged                                    |

`trigger-merge` no longer always merges the bare "next" commit. When dispatched **without** a
`merge-pick` SHA it chooses the commit to merge according to the `MERGAI_MERGE_PICK_MODE` variable,
and (in the `gate`/`ai` modes) only merges when the [merge gate](#merge-gate) is open — otherwise it
logs "no merge pick" and exits without creating a PR. Passing an explicit `merge-pick` SHA bypasses
both the mode and the gate (the manual "force this merge" path).

It also early-fails if any mergai branch (`main`/`conflict`/`solution`/`semantic`) already exists
for the chosen commit, so two runs can't race on the same merge.

### `periodic-merge.yml` ("mergai periodic merge")

Drives the merge loop without a human. It only _decides and triggers_ — all merge/conflict/PR
behavior stays in `mergai.yml`'s `trigger-merge` job, which it dispatches unchanged.

| Trigger                           | When it runs                                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `schedule` (cron)                 | Daily at 05:00 UTC, **only if** `MERGAI_PERIODIC_MERGE_ENABLED == 'true'`                                             |
| `workflow_dispatch`               | Always (manual test); **not** gated by the enable toggles                                                             |
| `pull_request` closed on `master` | Only if `MERGAI_FOLLOWUP_MERGE_ENABLED == 'true'` and a merged `mergai/*/main` PR — chains the next merge immediately |

The pick happens in two phases so AI tokens are only ever spent in the privileged job:

1. **Gate (here, token-free):** `mergai fork merge-pick --plan` decides _whether_ to merge (go/no-go
   over fork status). If the gate is closed, the workflow stops. It also stops early if a mergai PR
   is already open (a merge cycle is already underway).
2. **Pick + merge (in `trigger-merge`):** the workflow dispatches `mergai.yml` with **no** SHA;
   `trigger-merge` then picks the actual commit (deterministic or AI, per `MERGAI_MERGE_PICK_MODE`)
   and merges it.

> The cron _cadence_ is a literal in the workflow file — GitHub does not allow a variable there.
> `MERGAI_PERIODIC_MERGE_ENABLED` only turns scheduled runs on/off; to change the frequency, edit
> the `cron:` expression in `periodic-merge.yml`.

## Repository Variables

These are GitHub Actions **repository variables** (Settings → Secrets and variables → Actions →
**Variables** tab), _not_ secrets. All are optional; unset variables fall back to the defaults
below.

| Variable                        | Used by          | Default     | Purpose                                                                                                               |
| ------------------------------- | ---------------- | ----------- | --------------------------------------------------------------------------------------------------------------------- |
| `MERGAI_REF`                    | both workflows   | `master`    | Git ref (branch/tag/commit) of the mergai CLI to install. A `mergai-ref` dispatch input to `mergai.yml` overrides it. |
| `MERGAI_MERGE_PICK_MODE`        | `trigger-merge`  | `gate`      | How `trigger-merge` chooses which commit to merge when no SHA is given (see table below).                             |
| `MERGAI_PERIODIC_MERGE_ENABLED` | `periodic-merge` | off (unset) | `true` enables the scheduled (cron) periodic merge. Manual dispatch ignores this toggle.                              |
| `MERGAI_FOLLOWUP_MERGE_ENABLED` | `periodic-merge` | off (unset) | `true` chains the next merge automatically when a `mergai/*/main` PR is merged.                                       |

### Merge pick mode (`MERGAI_MERGE_PICK_MODE`)

Controls how `trigger-merge` selects the commit to merge **when dispatched without an explicit
`merge-pick` SHA**. An explicit SHA always bypasses the mode and the gate.

| Value                                                    | Honors gate? | Window cap? | How it picks the commit                                                                                                                               |
| -------------------------------------------------------- | ------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gate` _(default; also any unset or unrecognized value)_ | yes          | yes         | Deterministic: first prioritized strategy match within the candidate window, else the window tip (`merge-pick --gate`).                               |
| `ai`                                                     | yes          | yes         | An AI agent chooses the best merge boundary within the candidate window (`merge-pick --ai`; spends AI tokens, hence runs only in the privileged job). |
| `next`                                                   | **no**       | **no**      | Raw `merge-pick --next`: the first prioritized strategy match, with no gate and no window cap.                                                        |

In `gate` and `ai` modes, a closed gate (or nothing to merge) yields an empty pick and the merge
steps are skipped — no PR is created. `next` ignores the gate entirely.

## Merge Gate

The merge gate decides _when_ to merge (the pick decides _which_ commit). It is a pure go/no-go
decision over already-computed fork status — no AI tokens — and is configured in
`.mergai/config.yml` under `fork.merge_gate`:

- `min_commits` — merge once at least this many unmerged commits have accumulated (default 50).
- `max_age_days` — …or sooner if the oldest unmerged commit is older than this (default 2).
- `max_commits` — batch ceiling and candidate-window size; a single merge never advances more than
  this many commits (default 150).
- `force_strategies` — strategy names that open the gate immediately regardless of count or age
  (default `conflict`, `important_files`).

The AI pick is configured alongside it under `fork.ai_pick` (`agent`, `rules_file`, `fallback`); the
project rules it follows live in `.mergai/merge_pick_rules.md`.

> **`MERGAI_MERGE_PICK_MODE` selects which pick `trigger-merge` runs** — `gate` (deterministic),
> `ai`, or `next` — by calling `merge-pick --gate` / `--ai` / `--next` explicitly. The AI pick is
> always opt-in via `--ai`; the `fork.ai_pick` settings only tune how it behaves when selected.

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

Add commits directly to the branch. This works but commits won't be marked as solutions for future
reuse.

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

Ensure the PR branch is rebased onto (and fast-forwardable to) the base branch, then post a comment
with `/fast-forward` to merge without creating extra merge commits.

### Rebasing a stale mergai PR (`/mergai rebase`)

When the base branch (e.g. `master`) advances after a mergai PR is opened, the head branch is no
longer fast-forwardable and `/fast-forward` fails. Post a `/mergai rebase` comment on the PR and the
`rebase-handle` job in `mergai.yml` rebases the mergai branch onto the current base tip and
force-pushes it. The rebase preserves merge commits and mergai notes and reuses previously recorded
conflict solutions, so the PR becomes fast-forwardable again (then post `/fast-forward`).

Like `/fast-forward`, it runs under the `push-approve` environment (whereas `/mergai review fix`
uses `ai-approve`), so a required reviewer must approve the run before it acts. If the rebase hits conflicts it cannot
auto-resolve, the bot comments on the PR and you must rebase locally
(`mergai notes update && mergai context init && mergai rebase origin/<base>`).

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
mergai notes update     # Sync notes so recorded conflict solutions can be reused
mergai context init
mergai rebase
```

## Resources

- [Mergai Documentation](https://github.com/Percona-Lab/mergai#readme)
- [Fork Status Dashboard](https://percona.github.io/percona-server-mongodb/)
