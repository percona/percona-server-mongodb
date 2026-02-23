"""
Generate tasks for displaying bazel test results for all resmoke bazel tests.

This script creates a json config used in Evergreen's generate.tasks to add
tasks for displaying test results. It does not add the tasks to any variant.
They are added to variants by the resmoke_tests task based on which tests ran.

See also: buildscripts/append_result_tasks.py

Usage:
   bazel run //buildscripts:generate_result_tasks -- --outfile=generated_tasks.json

Options:
    --outfile           File path for the generated task config.
"""

import glob
import json
import os
import subprocess
import sys
from functools import cache
from typing import Optional

import runfiles
import typer
import yaml
from shrub.v2 import FunctionCall, Task
from typing_extensions import Annotated

RESMOKE_TEST_QUERY = 'attr(tags, "resmoke_suite_test", //...)'

app = typer.Typer(pretty_exceptions_show_locals=False)


def make_results_task(target: str) -> Task:
    commands = [
        FunctionCall("fetch remote test results", {"test_label": target}),
    ]

    task = Task(target, commands).as_dict()

    tag = get_assignment_tag(target)
    if tag:
        task["tags"] = [tag]

    return task


def get_assignment_tag(target: str) -> Optional[str]:
    # Format is like "assigned_to_jira_team_devprod_build".
    # See also docs/evergreen-testing/yaml_configuration/task_ownership_tags.md

    assignment_tags = resolve_assignment_tags()
    tags = set()
    for codeowner in get_codeowners(target):
        if codeowner in assignment_tags:
            tags.add(assignment_tags[codeowner])
    if len(tags) > 1:
        print(
            f"Target {target} has {len(tags)} possible assignment tags based on it's codeowner: {tags}. Picking the first encountered.",
            file=sys.stderr,
        )
    return list(tags)[0] if tags else None


def get_codeowners(target: str) -> list[str]:
    package = target.split(":", 1)[0]
    return resolve_codeowners().get(package)


@cache
def resolve_assignment_tags() -> dict[str, str]:
    try:
        # Find the teams directory in the runfiles. Unfortunately, resolving the
        # directory requires resolving a specific file within the runfiles, so
        # an arbitrary team's YAML is used.
        r = runfiles.Create()
        teams_dir = os.path.dirname(r.Rlocation("mothra/mothra/teams/devprod.yaml"))

        teams = []
        for file in glob.glob(teams_dir + "/*.yaml"):
            with open(file, "rt") as f:
                teams += yaml.safe_load(f).get("teams", [])

        assignment_tags = {}
        for team in teams:
            evergreen_tag_name = team.get("evergreen_tag_name")
            github_teams = team.get("code_owners", {}).get("github_teams", [])
            for github_team in github_teams:
                name = github_team.get("team_name")
                if name and evergreen_tag_name:
                    assignment_tags[name] = "assigned_to_jira_team_" + evergreen_tag_name
        return assignment_tags
    except Exception as e:
        # Conservatively except any exception here. In the worst case, the contents/format of the
        # Mothra repo could change out from under us, and it should not completely fail
        # task generation.
        print(f"Failed to resolve assignment tags: {e}", file=sys.stderr)
        return {}


@cache
def resolve_codeowners() -> dict[str, list[str]]:
    try:
        result = subprocess.run(
            'find * -name "BUILD.bazel" | xargs bazel run @codeowners_binary//:codeowners --',
            shell=True,
            capture_output=True,
            text=True,
            check=True,
        )

        codeowners_map = {}
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            # Each line is formatted like: "./buildscripts/BUILD.bazel     @owner1 @owner2 ..."
            words = line.split()
            package = "//" + words[0].removeprefix("./").removesuffix("/BUILD.bazel")
            # Remove teams that don't provide a meaningful mapping to a real owner.
            owners = set(words[1:])
            owners.difference_update({"@svc-auto-approve-bot", "@10gen/mongo-default-approvers"})

            codeowners_map[package] = [owner.removeprefix("@") for owner in owners]
        return codeowners_map
    except subprocess.CalledProcessError as e:
        print(f"Failed to resolve codeowners: {e.returncode}", file=sys.stderr)
        print(f"STDOUT:\n{e.stdout}", file=sys.stderr)
        print(f"STDERR:\n{e.stderr}", file=sys.stderr)
        return {}


def query_targets() -> list[str]:
    try:
        result = subprocess.run(
            ["bazel", "query", RESMOKE_TEST_QUERY],
            capture_output=True,
            text=True,
            check=True,
        )
        # Parse the output - each line is a target label
        return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Bazel query failed with return code {e.returncode}")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")
        raise


@app.command()
def main(outfile: Annotated[str, typer.Option()]):
    os.chdir(os.environ.get("BUILD_WORKSPACE_DIRECTORY", "."))

    test_targets = query_targets()

    tasks = [make_results_task(target) for target in test_targets]
    project = {"tasks": [task for task in tasks]}

    with open(outfile, "w") as f:
        f.write(json.dumps(project, indent=4))


if __name__ == "__main__":
    app()
