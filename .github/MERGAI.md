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

The pick happens in two phases so AI tokens are only ever spent in the secret-bearing
`trigger-merge` job (see
[Deployment environments & security model](#deployment-environments--security-model)):

1. **Gate (here, token-free):** `mergai fork merge-pick --plan` decides _whether_ to merge (go/no-go
   over fork status). If the gate is closed, the workflow stops. It also stops early if a mergai PR
   is already open (a merge cycle is already underway).
2. **Pick + merge (in `trigger-merge`):** the workflow dispatches `mergai.yml` with **no** SHA;
   `trigger-merge` then picks the actual commit (deterministic or AI, per `MERGAI_MERGE_PICK_MODE`)
   and merges it.

> The cron _cadence_ is a literal in the workflow file — GitHub does not allow a variable there.
> `MERGAI_PERIODIC_MERGE_ENABLED` only turns scheduled runs on/off; to change the frequency, edit
> the `cron:` expression in `periodic-merge.yml`.

## Deployment Environments & Security Model

GitHub Actions **deployment environments** are the security boundary for the mergai workflows. Each
environment does two independent things:

1. **Carries secrets** — a job can read an environment's secrets only if it declares that
   environment.
2. **Optionally gates on human approval** — an environment with _required reviewers_ pauses any job
   targeting it until a reviewer approves the deployment.

We keep those two concerns separate, so environments come in pairs: `<purpose>` (ungated) and
`<purpose>-approve` (approval-gated by the `dev-psmdb-approvers` team).

| Environment        | Secrets it carries             | Approval           | Deployment branches             |
| ------------------ | ------------------------------ | ------------------ | ------------------------------- |
| `ai`               | AI-agent creds                 | none               | `master`, `mergai/**`           |
| `ai-approve`       | same AI creds                  | required reviewers | none (the reviewer is the gate) |
| `push-approve`     | none (App token is repo-level) | required reviewers | none                            |
| `rbe`              | RBE OIDC secrets               | none               | all branches (see below)        |
| `rbe-approve`      | same RBE OIDC secrets          | required reviewers | none                            |
| _(no environment)_ | none (App token is repo-level) | none               | —                               |

The GitHub App token (`PSMDB_BOT_GH_APP_ID` / `PSMDB_BOT_GH_APP_PRIVATE_KEY`) is a
**repository-level** secret, so any job can mint a write token without an environment — which is why
the finalize jobs run under no environment at all.

> **Operator note:** create all five environments in **Settings → Environments** (with the
> reviewers, secrets, and deployment branches above) **before** these workflows first run. GitHub
> auto-creates a referenced-but-undefined environment with **no** protection rules, which would
> silently open the gated paths.

### Why this is safe

Three structural facts underpin the whole model:

1. **The gating logic can't be self-promoted.** For `pull_request_target`, `workflow_run`,
   `issue_comment` and `pull_request_review`, GitHub always reads the workflow file from the
   **base/default branch**, never the PR head. A PR that edits `mergai.yml` / `build-and-test.yml`
   to route itself to an ungated environment does **not** change the gating of its own run.
2. **Ungated environments can't be reached from an untrusted ref.** `ai`'s deployment-branch policy
   allows only `master` + `mergai/**`. `workflow_dispatch` can be triggered on _any_ ref, but a run
   dispatched on another branch is **denied the `ai` secrets** by that policy — so the environment's
   branch policy (not the trigger) is what stops a feature branch from reading the AI secrets. `rbe`
   is deliberately **not** branch-restricted: `build-and-test.yml` runs on `pull_request_target`,
   and GitHub evaluates the environment deployment-branch rule against the **PR head branch**, so
   any restriction would block ordinary same-repo PR builds (feature branches). What keeps untrusted
   (fork) code off `rbe` is the same-repo **gate ternary** — fork PRs resolve to `rbe-approve` and
   require approval — together with the fact that `build-and-test.yml` is the only workflow that
   references `rbe`, and only via `pull_request_target` (whose workflow file is read from the base
   branch, so a PR can't add its own `rbe` reference). The approval-gated environments need no
   branch restriction either — the required reviewer is the control.
3. **Trust is decided by the trigger, not a spoofable field.** A job runs ungated only when the
   _trigger itself_ proves the actor has write access (see below). `author_association` is never
   used to skip a required-reviewer gate; the CLI's `trusted_associations` allow-list is a
   _post-approval_ content filter (which commenters the agent acts on after `ai-approve`), not a
   deployment bypass.

### Per-job rationale

The question for every job is: **does the trigger inherently prove the actor has write access?** If
yes → ungated. If no → approval-gated. If the job needs no secrets at all → no environment.

| Workflow                       | Job(s)                                                    | Trigger                                                                             | Environment            | Approval | Why                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------ | --------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mergai.yml`                   | `trigger-merge`                                           | `workflow_dispatch`                                                                 | `ai`                   | No       | Only users with **write access** can dispatch a workflow (GitHub platform rule), so the trigger _is_ the trust boundary — an approval would be redundant. Runs the AI agent, so needs the AI secrets.                                                                                                                                                                    |
| `mergai.yml`                   | `solution-merged`, `semantic-merged`                      | `pull_request` closed with `merged == true`                                         | _(none)_               | No       | Only a **write-access** user can merge a PR, so `merged == true` proves trust. These jobs finalize with the repo-level App token only — no AI/RBE secrets — so they need no environment.                                                                                                                                                                                 |
| `mergai.yml`                   | `ci-gate`                                                 | `workflow_run` on `mergai/**`, same-repo only                                       | _(none)_               | No       | Read-only: computes the aggregate CI state with the default `GITHUB_TOKEN`. No secrets, no writes → no environment and no approval. Still carries the same-repo guard (see `ci-handle`) so a fork can't drive the state machine.                                                                                                                                         |
| `mergai.yml`                   | `ci-handle`                                               | `workflow_run` on `mergai/**` + `ci-gate` failure, same-repo only                   | `ai`                   | No       | The `mergai/**` branch filter is **not** sufficient — a fork PR can name its head branch `mergai/...` and spoof `workflow_run.head_branch`. The real trust boundary is the same-repo guard `workflow_run.head_repository.full_name == github.repository` (on both `ci-gate` and `ci-handle`); do not remove it as redundant. Runs the AI fixer, so needs the AI secrets. |
| `mergai.yml`                   | `review-handle`                                           | `issue_comment` `/mergai review fix` **or** `pull_request_review` changes-requested | `ai-approve`           | **Yes**  | A comment or review can come from **any** user — not inherently trusted. Approval is required before the AI agent and secrets are exposed. The CLI `process_external: false` filter is a second layer (untrusted authors' instructions are ignored even after approval).                                                                                                 |
| `mergai.yml`                   | `rebase-handle`                                           | `issue_comment` `/mergai rebase`                                                    | `push-approve`         | **Yes**  | Any user can comment → approval required. Force-pushes the mergai branch; needs only the App token, so no AI/RBE secrets.                                                                                                                                                                                                                                                |
| `fast-forward.yml`             | `fast-forward`                                            | `issue_comment` `/fast-forward`                                                     | `push-approve`         | **Yes**  | Any user can comment, and the job **pushes to `master`** (protected). Approval is the primary gate; the in-job `getCollaboratorPermissionLevel` check (write/maintain/admin) and fork-PR rejection are a second layer.                                                                                                                                                   |
| `build-and-test.yml`           | `gate`                                                    | `pull_request_target`                                                               | `rbe` \| `rbe-approve` | Cond.    | A branch exists in this repo only if a **write-access** actor pushed it, so same-repo (`head.repo.full_name == github.repository`) → ungated `rbe`; fork/external PRs → `rbe-approve` (approval). The single `gate` approval authorizes the whole downstream pipeline.                                                                                                   |
| `build-and-test.yml`           | `build`, `unittests`, `dbtests`, `jstests`                | `needs: gate`                                                                       | `rbe`                  | Inherit  | Run only after `gate` (transitively via `needs`), so the gate is the single approval point. Local resmoke execution of PR-head code is therefore reached only after the gate passed — same-repo (trusted) or an `rbe-approve` reviewer approved a fork PR.                                                                                                               |
| `build-and-test.yml`           | `format_gate`, `jstests_gate`                             | `pull_request_target`                                                               | _(none)_               | No       | Label/skip decision jobs (whether format / jstests run). Read-only, no secrets, no environment.                                                                                                                                                                                                                                                                          |
| `periodic-merge.yml`           | `periodic-merge` (decide + dispatch)                      | `schedule` / `workflow_dispatch` / `pull_request` closed on `master`                | _(none)_               | No       | Token-free go/no-go decision, then dispatches `trigger-merge` with the App token. Triggers are repo-controlled (dispatch requires write; schedule is repo-controlled; the follow-up is gated by a repo variable). The secret-bearing work is deferred to `trigger-merge` (`ai`).                                                                                         |
| `update-fork-status.yml`       | `update-status`                                           | `push` to `master` / `workflow_dispatch` / `schedule`                               | _(none)_               | No       | Publishes the fork-status dashboard with the App token. All triggers are trusted (push to `master` and dispatch require write access; schedule is repo-controlled). No secrets beyond the App token.                                                                                                                                                                     |
| `format.yml`, `clang-tidy.yml` | `check-skip`, `analyze` (+ `changed_files` in clang-tidy) | `pull_request`                                                                      | _(none)_               | No       | Plain `pull_request` (not `_target`): runs in the fork's context with a **read-only** token and **no** access to secrets, so untrusted PR code can never reach a secret. No environment needed.                                                                                                                                                                          |

**Net effect.** The trusted day-to-day loop — periodic merges, team-dispatched merges, merge
finalization, and automated CI fixes on the bot-created `mergai/**` branches — runs with **zero**
approvals. The only runs that pause for a `dev-psmdb-approvers` click are the ones whose trigger
cannot prove write access: comment/review-driven commands (`review-handle`, `rebase-handle`,
`fast-forward`) and CI for fork/external PRs (`rbe-approve`).

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

| Value                                                    | Honors gate? | Window cap? | How it picks the commit                                                                                                                                                   |
| -------------------------------------------------------- | ------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gate` _(default; also any unset or unrecognized value)_ | yes          | yes         | Deterministic: first prioritized strategy match within the candidate window, else the window tip (`merge-pick --gate`).                                                   |
| `ai`                                                     | yes          | yes         | An AI agent chooses the best merge boundary within the candidate window (`merge-pick --ai`; spends AI tokens, hence runs only in the secret-bearing `trigger-merge` job). |
| `next`                                                   | **no**       | **no**      | Raw `merge-pick --next`: the first prioritized strategy match, with no gate and no window cap.                                                                            |

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
uses `ai-approve`), so a required reviewer must approve the run before it acts. If the rebase hits
conflicts it cannot auto-resolve, the bot comments on the PR and you must rebase locally
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
