"""Append a pass/fail summary of Bazel test targets to the GitHub job summary.

Reads the Build Event Protocol JSON (Bazel's --build_event_json_file), building on
the testSummary parse in buildscripts/gather_failed_tests.py. The BEP is always
written locally and carries a testSummary event per target with its overallStatus
-- unlike test.xml, which under --remote_download_outputs=minimal stays in the
remote cache and is not on the runner.

A target is reported as one of three outcomes so a cancelled or interrupted run
stays honest:
  * passed     -- overallStatus PASSED or FLAKY (passed on retry);
  * failed     -- a failing overallStatus, OR any individual testResult failed
                  (the latter catches a real failure even when the suite's
                  aggregate summary never finalized because the run was killed);
  * incomplete -- a target that was started but never reached a verdict
                  (NO_STATUS / INCOMPLETE), e.g. the in-flight suite when the
                  workflow is cancelled.

With --detailed (used for unittests), the summary also reports how many targets
actually executed vs were served from cache (per-testResult cachedLocally /
executionInfo.cachedRemotely) and adds a collapsible per-target table.

Writes Markdown to $GITHUB_STEP_SUMMARY (or stdout when unset, for local runs).
Always exits 0 -- reporting must never mask the real `bazel test` exit code.
"""

import argparse
import glob
import json
import os
import sys

PASSING = {"PASSED", "FLAKY"}
FAILING = {"FAILED", "TIMEOUT", "REMOTE_FAILURE", "FAILED_TO_BUILD"}

# Render order and icon for each outcome.
OUTCOME_RANK = {"failed": 0, "incomplete": 1, "skipped": 2, "passed": 3}
OUTCOME_ICON = {"failed": "❌", "incomplete": "⚠️", "skipped": "⚪", "passed": "✅"}


def summary_duration_ms(summary):
    """Wall-clock duration of a target in ms: last stop minus first start, with
    totalRunDurationMillis (cumulative across shards/runs) as a fallback."""
    start = summary.get("firstStartTimeMillis")
    stop = summary.get("lastStopTimeMillis")
    try:
        if start is not None and stop is not None:
            return max(0, int(stop) - int(start))
    except (TypeError, ValueError):
        pass
    try:
        return int(summary["totalRunDurationMillis"])
    except (KeyError, TypeError, ValueError):
        return None


def fmt_duration(ms):
    if ms is None:
        return "—"
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000.0
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def parse_bep(paths):
    """Return {label: {outcome, cached, failed_runs, total_runs, duration_ms}} from BEP."""
    summaries = {}  # label -> (overallStatus, failed_runs, total_runs)
    result_failed = set()  # labels with at least one failing individual testResult
    executed = set()  # labels with at least one freshly-executed testResult
    cached = set()  # labels with at least one cache-hit testResult
    skipped = set()  # labels skipped by --test_tag_filters (aborted/SKIPPED, no testSummary)
    for path in paths:
        with open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_id = event.get("id", {})
                if "testSummary" in event_id:
                    label = event_id["testSummary"]["label"]
                    summary = event["testSummary"]
                    status = summary.get("overallStatus", "NO_STATUS")
                    entry = (
                        status,
                        len(summary.get("failed", [])),
                        summary.get("totalRunCount", 0),
                        summary_duration_ms(summary),
                    )
                    # If a label recurs across invocations, keep the worst outcome.
                    prev = summaries.get(label)
                    if prev is None or (status not in PASSING and prev[0] in PASSING):
                        summaries[label] = entry
                elif "testResult" in event_id:
                    label = event_id["testResult"]["label"]
                    result = event.get("testResult", {})
                    if result.get("status") in FAILING:
                        result_failed.add(label)
                    if result.get("cachedLocally") or result.get("executionInfo", {}).get(
                        "cachedRemotely"
                    ):
                        cached.add(label)
                    else:
                        executed.add(label)
                elif event.get("aborted", {}).get("reason") == "SKIPPED":
                    # A target filtered out by --test_tag_filters: reported as an
                    # aborted/SKIPPED event with no testSummary/testResult.
                    label = event_id.get("targetCompleted", {}).get("label")
                    if label:
                        skipped.add(label)

    targets = {}
    for label in set(summaries) | result_failed | skipped:
        if label in skipped and label not in summaries and label not in result_failed:
            targets[label] = {
                "outcome": "skipped",
                "cached": False,
                "failed_runs": 0,
                "total_runs": 0,
                "duration_ms": None,
            }
            continue
        status, failed_runs, total_runs, duration_ms = summaries.get(
            label, ("NO_STATUS", 0, 0, None)
        )
        # Check PASSING first: a finalized PASSED/FLAKY verdict wins even when the
        # BEP also carries a failed individual testResult (a flaky suite logs the
        # losing run before the passing retry). result_failed only decides the
        # outcome when the summary never finalized (NO_STATUS / INCOMPLETE).
        if status in PASSING:
            outcome = "passed"
        elif status in FAILING or label in result_failed:
            outcome = "failed"
        else:
            outcome = "incomplete"
        targets[label] = {
            "outcome": outcome,
            # Cached only if it was served from cache and never freshly executed.
            "cached": label in cached and label not in executed,
            "failed_runs": failed_runs,
            "total_runs": total_runs,
            "duration_ms": duration_ms,
        }
    return targets


def parse_resmoke(paths):
    """Return {test_file: {outcome, cached, failed_runs, total_runs, duration_ms}}
    from resmoke report.json file(s).

    Used by the dbtests job, which runs resmoke LOCALLY (the dbtest binary has no
    Bazel test target, so there is no BEP). The report schema is
    {"results": [{"test_file", "status", "exit_code", "start", "end", ...}]}
    where status is an Evergreen status string. Outcomes are mapped to match
    parse_bep so render() is shared:
      * pass                  -> passed;
      * skip / silentfail     -> skipped (silentfail is a silenced/known failure);
      * anything else         -> failed (fail, timeout, error, ...).
    """
    targets = {}
    for path in paths:
        try:
            with open(path, "rt", encoding="utf-8", errors="replace") as fh:
                results = json.load(fh).get("results", [])
        except (OSError, ValueError):
            continue
        for r in results:
            label = r.get("test_file") or r.get("display_test_name") or "?"
            status = (r.get("status") or "").lower()
            if status == "pass":
                outcome = "passed"
            elif status in ("skip", "silentfail"):
                outcome = "skipped"
            else:
                outcome = "failed"
            duration_ms = None
            start, end = r.get("start"), r.get("end")
            try:
                if start is not None and end is not None:
                    duration_ms = max(0, int((float(end) - float(start)) * 1000))
            except (TypeError, ValueError):
                duration_ms = None
            failed_run = 1 if outcome == "failed" else 0
            prev = targets.get(label)
            if prev is None:
                targets[label] = {
                    "outcome": outcome,
                    "cached": False,
                    "failed_runs": failed_run,
                    "total_runs": 1,
                    "duration_ms": duration_ms,
                }
            else:
                # A test can recur in one report (e.g. --repeatTests). Accumulate
                # the run counts/duration across the repeats and keep the worst
                # outcome, so the summary reflects every run rather than just the
                # last one.
                prev["total_runs"] += 1
                prev["failed_runs"] += failed_run
                if duration_ms is not None:
                    prev["duration_ms"] = (prev["duration_ms"] or 0) + duration_ms
                if outcome == "failed":
                    prev["outcome"] = "failed"
    return targets


def render(targets, title, detailed):
    out = [f"## {title}", ""]
    if not targets:
        out.append("⚠️ No test results found.")
        return "\n".join(out) + "\n"

    failed = sorted(l for l, t in targets.items() if t["outcome"] == "failed")
    incomplete = sorted(l for l, t in targets.items() if t["outcome"] == "incomplete")
    skipped = sorted(l for l, t in targets.items() if t["outcome"] == "skipped")
    passed = len(targets) - len(failed) - len(incomplete) - len(skipped)

    counts = []
    if failed:
        counts.append(f"{len(failed)} failed")
    if incomplete:
        counts.append(f"{len(incomplete)} incomplete")
    counts.append(f"{passed} passed")
    if skipped:
        counts.append(f"{len(skipped)} skipped")
    icon = "❌" if failed else ("⚠️" if incomplete else "✅")
    headline = f"{icon} {', '.join(counts)} ({len(targets)} targets)"
    if detailed:
        # executed/cached are over the targets that actually ran (not skipped).
        tested = len(targets) - len(skipped)
        cached = sum(1 for t in targets.values() if t["cached"])
        headline += f" — {tested - cached} executed, {cached} cached"
    out.append(headline)

    if failed or incomplete:
        out += ["", "### Failures", "", "| Target | Status | Runs failed |", "| --- | --- | --- |"]
        for label in failed:
            t = targets[label]
            out.append(f"| `{label}` | failed | {t['failed_runs']}/{t['total_runs'] or '?'} |")
        for label in incomplete:
            out.append(f"| `{label}` | incomplete (no verdict) | — |")

    if skipped:
        out += ["", f"<details><summary>{len(skipped)} skipped</summary>", ""]
        out += [f"- `{label}`" for label in skipped]
        out += ["", "</details>"]

    if detailed:
        out += ["", f"<details><summary>All {len(targets)} targets</summary>", ""]
        out += ["| Target | Status | Time | Runs | Source |", "| --- | --- | --- | --- | --- |"]
        for label in sorted(targets, key=lambda l: (OUTCOME_RANK[targets[l]["outcome"]], l)):
            t = targets[label]
            if t["outcome"] == "skipped":
                source = "—"
            else:
                source = "cached" if t["cached"] else "executed"
            runs = str(t["total_runs"]) if t["total_runs"] else "—"
            out.append(
                f"| `{label}` | {OUTCOME_ICON[t['outcome']]} {t['outcome']} "
                f"| {fmt_duration(t['duration_ms'])} | {runs} | {source} |"
            )
        out += ["", "</details>"]

    out.append("")
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bep_glob", nargs="?", default="bazel-bep*.json", help="glob for BEP JSON file(s)"
    )
    parser.add_argument("--title", default="🧪 Test results", help="summary heading")
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="add executed/cached counts and a per-target table",
    )
    parser.add_argument(
        "--resmoke-report",
        default="",
        help=(
            "glob for resmoke report.json file(s) from a LOCAL resmoke run (e.g. the "
            "dbtests job). Merged into the BEP targets so render() is shared."
        ),
    )
    args = parser.parse_args()

    bep_paths = sorted(glob.glob(args.bep_glob)) if args.bep_glob else []
    targets = parse_bep(bep_paths)

    resmoke_paths = sorted(glob.glob(args.resmoke_report)) if args.resmoke_report else []
    if resmoke_paths:
        targets.update(parse_resmoke(resmoke_paths))

    text = render(targets, args.title, args.detailed)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    print(
        f"github_test_summary: {len(bep_paths)} BEP file(s), "
        f"{len(resmoke_paths)} resmoke report(s), {len(targets)} target(s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    # Reporting must never mask the real test exit code.
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"github_test_summary: non-fatal error: {exc}", file=sys.stderr)
    sys.exit(0)
