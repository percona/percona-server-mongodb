import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import traceback
import unittest
from collections.abc import Sequence
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from buildscripts.copybara import generate_evergreen, sync_repo_with_copybara
from buildscripts.copybara.path_rules import render_copybara_path_rules_module_from_files

DEFAULT_COMMON_EXCLUDED_PATTERNS = [
    ".agents/**",
    ".claude/**",
    ".cursor/**",
    ".github/CODEOWNERS",
    ".github/workflows/**",
    "AGENTS.md",
    "CLAUDE.md",
    "buildscripts/copybara/**",
    "buildscripts/modules/**",
    "etc/evergreen_yml_components/**",
    "monguard/**",
    "sbom.private.json",
    "src/mongo/db/modules/**",
    "src/third_party/private/**",
]

DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES = ("**",)
DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES = tuple(DEFAULT_COMMON_EXCLUDED_PATTERNS)

REPO_COPYBARA_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "buildscripts"
    / "copybara"
    / "copybara_path_rules.bara.sky.template"
)


def get_repo_base_copybara_config_path(root: Path) -> Path:
    return root / sync_repo_with_copybara.COPYBARA_BASE_CONFIG_PATH


def get_repo_copybara_path_rules_path(root: Path) -> Path:
    return root / sync_repo_with_copybara.COPYBARA_PATH_RULES_PATH


def get_repo_copybara_path_rules_template_path(root: Path) -> Path:
    return root / sync_repo_with_copybara.COPYBARA_PATH_RULES_TEMPLATE_PATH


def get_repo_copybara_path_rules_module_path(root: Path) -> Path:
    return root / sync_repo_with_copybara.COPYBARA_PATH_RULES_MODULE_PATH


def write_copybara_path_rules(
    path: Path,
    *,
    common_includes: Sequence[str],
    common_excludes: Sequence[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "common_files_to_include": list(common_includes),
                "common_files_to_exclude": list(common_excludes),
            },
            indent=2,
        )
        + "\n"
    )


def write_copybara_path_rules_module(path: Path, path_rules_path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_copybara_path_rules_module_from_files(
            REPO_COPYBARA_TEMPLATE_PATH,
            path_rules_path,
        )
    )


def write_copybara_path_rules_template(path: Path, template_text: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if template_text is None:
        template_text = REPO_COPYBARA_TEMPLATE_PATH.read_text()
    path.write_text(template_text)


@unittest.skipIf(
    sys.platform == "win32" or sys.platform == "darwin",
    reason="No need to run this unittest on windows or macos",
)
class TestBranchFunctions(unittest.TestCase):
    @staticmethod
    def create_mock_repo_git_config(mongodb_mongo_dir, config_content):
        """
        Create a mock Git repository configuration.

        :param mongodb_mongo_dir: The directory path of the mock MongoDB repository.
        :param config_content: The content to be written into the Git configuration file.
        """
        os.makedirs(mongodb_mongo_dir, exist_ok=True)

        # Create .git directory
        git_dir = os.path.join(mongodb_mongo_dir, ".git")
        os.makedirs(git_dir, exist_ok=True)

        # Write contents to .git/config
        config_path = os.path.join(git_dir, "config")
        with open(config_path, "w") as f:
            # Write contents to .git/config
            f.write(config_content)

    @staticmethod
    def create_mock_repo_commits(repo_directory, num_commits, private_commit_hashes=None):
        """
        Create mock commits in a Git repository.

        :param repo_directory: The directory path of the Git repository where the commits will be created.
        :param num_commits: The number of commits to create.
        :param private_commit_hashes: Optional. A list of private commit hashes to be included in the commit messages.
        :return: A list of commit hashes generated for the new commits.
        """
        os.chdir(repo_directory)
        sync_repo_with_copybara.run_command("git init")
        sync_repo_with_copybara.run_command('git config --local user.email "test@example.com"')
        sync_repo_with_copybara.run_command('git config --local user.name "Test User"')
        sync_repo_with_copybara.run_command("git config --local commit.gpgsign false")
        # Used to store commit hashes
        commit_hashes = []
        for i in range(num_commits):
            with open("test.txt", "a") as f:
                f.write(str(i))

            sync_repo_with_copybara.run_command("git add test.txt")
            commit_message = f"test commit {i}"
            # If there are private commit hashes need to be added in public repo commits, include them in the commit message
            if private_commit_hashes:
                commit_message += f"\nGitOrigin-RevId: {private_commit_hashes[i]}"

            # Get the current commit hash
            sync_repo_with_copybara.run_command(f'git commit -m "{commit_message}"')
            commit_hashes.append(
                sync_repo_with_copybara.run_command('git log --pretty=format:"%H" -1')
            )
        return commit_hashes

    @staticmethod
    def create_repo_branch(repo_directory, branch_name):
        """
        Create a branch in a Git repository

        :param repo_directory: The directory path of the Git repository where the branch will be created.
        :param branch_name: The name of the new branch
        """
        os.chdir(repo_directory)
        sync_repo_with_copybara.run_command(f"git branch {branch_name}")

    @staticmethod
    def mock_search(test_name, num_commits, matched_public_commits):
        """
        Mock search function to simulate finding matching commits.

        :param test_name: The name of the test.
        :param num_commits: The number of commits in the repository.
        :param matched_public_commits: The number of commits in the public repository that match the private repository with tag 'GitOrigin-RevId'.
        :return: True if the last commit in the search result matches the last commit in the public repository, False otherwise.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                mock_10gen_dir = os.path.join(tmpdir, "mock_10gen")
                mock_mongodb_dir = os.path.join(tmpdir, "mock_mongodb")
                os.mkdir(mock_10gen_dir)
                os.mkdir(mock_mongodb_dir)

                os.chdir(mock_10gen_dir)
                # Create a mock private repository and get all commit hashes
                private_hashes = TestBranchFunctions.create_mock_repo_commits(
                    mock_10gen_dir, num_commits
                )

                # Create a mock public repository and pass the list of private commit hashes
                if matched_public_commits != 0:
                    public_hashes = TestBranchFunctions.create_mock_repo_commits(
                        mock_mongodb_dir, matched_public_commits, private_hashes
                    )
                else:
                    public_hashes = TestBranchFunctions.create_mock_repo_commits(
                        mock_mongodb_dir, num_commits
                    )

                os.chdir(tmpdir)
                result = sync_repo_with_copybara.find_matching_commit(
                    mock_10gen_dir, mock_mongodb_dir
                )

                # Check if the commit in the search result matches the last commit in the public repository
                if result == public_hashes[-1]:
                    return True
                else:
                    assert result is None
            except Exception as err:
                print(f"{test_name}: FAIL!\n Exception occurred: {err}\n {traceback.format_exc()}")
                return False

    def test_no_search(self):
        """Perform a test where no search is required."""
        test_name = "no_search_test"
        result = self.mock_search(test_name, 5, 5)
        self.assertTrue(result, f"{test_name}: SUCCESS!")

    def test_search(self):
        """Perform a test where searching back 5 commits to find the matching commit."""
        test_name = "search_test"
        result = self.mock_search(test_name, 10, 5)
        self.assertTrue(result, f"{test_name}: SUCCESS!")

    def test_no_commit_found(self):
        """Perform a test where no matching commit is found."""
        test_name = "no_commit_found_test"
        result = self.mock_search(test_name, 2, 0)
        self.assertIsNone(result, f"{test_name}: SUCCESS!")

    def test_prefers_newest_destination_commit_for_duplicate_origin_rev_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            destination_dir = os.path.join(tmpdir, "destination")
            os.mkdir(source_dir)
            os.mkdir(destination_dir)

            private_hashes = TestBranchFunctions.create_mock_repo_commits(source_dir, 1)
            public_hashes = TestBranchFunctions.create_mock_repo_commits(
                destination_dir,
                2,
                [private_hashes[0], private_hashes[0]],
            )

            result = sync_repo_with_copybara.find_matching_commit(source_dir, destination_dir)
            self.assertEqual(result, public_hashes[-1])

    def test_find_matching_commit_pair_returns_source_and_destination(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            destination_dir = os.path.join(tmpdir, "destination")
            os.mkdir(source_dir)
            os.mkdir(destination_dir)

            private_hashes = TestBranchFunctions.create_mock_repo_commits(source_dir, 3)
            public_hashes = TestBranchFunctions.create_mock_repo_commits(
                destination_dir,
                2,
                [private_hashes[0], private_hashes[1]],
            )

            result = sync_repo_with_copybara.find_matching_commit_pair(source_dir, destination_dir)

            self.assertEqual(
                result,
                sync_repo_with_copybara.MatchingCommit(
                    source_commit=private_hashes[1],
                    destination_commit=public_hashes[-1],
                ),
            )

    def test_branch_exists(self):
        """Perform a test to check that the branch exists in a repository."""
        test_name = "branch_exists_test"
        branch = "v0.0"

        with tempfile.TemporaryDirectory() as tmpdir:
            remote_repo_dir = os.path.join(tmpdir, "remote_repo")
            os.mkdir(remote_repo_dir)
            self.create_mock_repo_commits(remote_repo_dir, 1)
            self.create_repo_branch(remote_repo_dir, branch)

            copybara_config = sync_repo_with_copybara.CopybaraConfig(
                source=None,
                destination=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=remote_repo_dir,
                    branch=branch,
                ),
            )
            result = sync_repo_with_copybara.check_destination_branch_exists(copybara_config)
            self.assertTrue(result, f"{test_name}: SUCCESS!")

    def test_branch_not_exists(self):
        """Perform a test to check that the branch does not exist in a repository."""
        test_name = "branch_not_exists_test"
        branch = "..invalid-therefore-impossible-to-create-branch-name"

        with tempfile.TemporaryDirectory() as tmpdir:
            remote_repo_dir = os.path.join(tmpdir, "remote_repo")
            os.mkdir(remote_repo_dir)
            self.create_mock_repo_commits(remote_repo_dir, 1)

            copybara_config = sync_repo_with_copybara.CopybaraConfig(
                source=None,
                destination=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=remote_repo_dir,
                    branch=branch,
                ),
            )
            result = sync_repo_with_copybara.check_destination_branch_exists(copybara_config)
            self.assertFalse(result, f"{test_name}: SUCCESS!")

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_branch_exists_remote_requires_exact_branch_match(self, mock_run_command):
        mock_run_command.return_value = "\n".join(
            [
                "08995ea824ba2492ba1e496a2fb58e80ea2d22c3\trefs/heads/markbenvenuto/master",
                "b4dbdfd07f20ec4e0f4873bff4059073c9da62c4\trefs/heads/sql/master",
            ]
        )

        self.assertFalse(
            sync_repo_with_copybara.branch_exists_remote("https://example.com/source.git", "master")
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_get_remote_branch_head_prefers_exact_branch_match(self, mock_run_command):
        mock_run_command.return_value = "\n".join(
            [
                "08995ea824ba2492ba1e496a2fb58e80ea2d22c3\trefs/heads/markbenvenuto/master",
                "78efcf74c13378efe35e4e49fdf7cf0c9206af56\trefs/heads/master",
                "b4dbdfd07f20ec4e0f4873bff4059073c9da62c4\trefs/heads/sql/master",
            ]
        )

        self.assertEqual(
            sync_repo_with_copybara.get_remote_branch_head(
                "https://example.com/source.git", "master"
            ),
            "78efcf74c13378efe35e4e49fdf7cf0c9206af56",
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_check_destination_branch_exists_requires_exact_branch_match(self, mock_run_command):
        mock_run_command.return_value = "\n".join(
            [
                "08995ea824ba2492ba1e496a2fb58e80ea2d22c3\trefs/heads/markbenvenuto/master",
                "b4dbdfd07f20ec4e0f4873bff4059073c9da62c4\trefs/heads/sql/master",
            ]
        )

        self.assertFalse(
            sync_repo_with_copybara.check_destination_branch_exists(
                sync_repo_with_copybara.CopybaraConfig(
                    destination=sync_repo_with_copybara.CopybaraRepoConfig(
                        git_url="https://example.com/destination.git",
                        branch="master",
                    )
                )
            )
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_check_destination_branch_exists_accepts_exact_branch_match(self, mock_run_command):
        mock_run_command.return_value = "\n".join(
            [
                "78efcf74c13378efe35e4e49fdf7cf0c9206af56\trefs/heads/master",
                "b4dbdfd07f20ec4e0f4873bff4059073c9da62c4\trefs/heads/sql/master",
            ]
        )

        self.assertTrue(
            sync_repo_with_copybara.check_destination_branch_exists(
                sync_repo_with_copybara.CopybaraConfig(
                    destination=sync_repo_with_copybara.CopybaraRepoConfig(
                        git_url="https://example.com/destination.git",
                        branch="master",
                    )
                )
            )
        )

    def test_only_mongodb_mongo_repo(self):
        """Perform a test that the repository is only the MongoDB official repository."""
        test_name = "only_mongodb_mongo_repo_test"

        # Define the content for the Git configuration file
        config_content = "blalla\n"
        config_content += "url = git@github.com:mongodb/mongo.git "

        with tempfile.TemporaryDirectory() as tmpdir:
            mongodb_mongo_dir = os.path.join(tmpdir, "mock_mongodb_mongo_repo")
            # Create Git configuration file
            self.create_mock_repo_git_config(mongodb_mongo_dir, config_content)
            os.chdir(mongodb_mongo_dir)

            try:
                # Check if the repository is only the MongoDB official repository
                result = sync_repo_with_copybara.has_only_destination_repo_remote("mongodb/mongo")
            except Exception as err:
                print(f"{test_name}: FAIL!\n Exception occurred: {err}\n {traceback.format_exc()}")
                self.fail(f"{test_name}: FAIL!")
                return

            self.assertTrue(result, f"{test_name}: SUCCESS!")

    def test_not_only_mongodb_mongo_repo(self):
        """Perform a test that the repository is not only the MongoDB official repository."""
        test_name = "not_only_mongodb_mongo_repo_test"

        # Define the content for the Git configuration file
        config_content = "blalla\n"
        config_content += "url = git@github.com:mongodb/mongo.git "
        config_content += "url = git@github.com:10gen/mongo.git "

        with tempfile.TemporaryDirectory() as tmpdir:
            mongodb_mongo_dir = os.path.join(tmpdir, "mock_mongodb_mongo_repo")

            # Create Git configuration file with provided content
            self.create_mock_repo_git_config(mongodb_mongo_dir, config_content)

            try:
                # Call function to push branch to public repository, expecting an exception
                sync_repo_with_copybara.push_branch_to_destination_repo(
                    mongodb_mongo_dir,
                    copybara_config=sync_repo_with_copybara.CopybaraConfig(
                        source=sync_repo_with_copybara.CopybaraRepoConfig(
                            git_url="",
                            repo_name="",
                            branch="",
                        ),
                        destination=sync_repo_with_copybara.CopybaraRepoConfig(
                            git_url="",
                            repo_name="",
                            branch="",
                        ),
                    ),
                    branching_off_commit="",
                )
            except Exception as err:
                if (
                    str(err)
                    == f"{mongodb_mongo_dir} git repo has not only the destination repo remote"
                ):
                    return

            self.fail(f"{test_name}: FAIL!")

    def test_new_branch_commits_not_match_branching_off_commit(self):
        """Perform a test that the new branch commits do not match the branching off commit."""
        test_name = "new_branch_commits_not_match_branching_off_commit_test"

        # Define the content for the Git configuration file
        config_content = "blalla\n"
        config_content += "url = git@github.com:mongodb/mongo.git "

        # Define a invalid branching off commit
        invalid_branching_off_commit = "123456789"

        with tempfile.TemporaryDirectory() as tmpdir:
            mongodb_mongo_dir = os.path.join(tmpdir, "mock_mongodb_mongo_repo")

            # Create Git configuration file with provided content
            self.create_mock_repo_git_config(mongodb_mongo_dir, config_content)
            os.chdir(mongodb_mongo_dir)

            # Create some mock commits in the repository
            self.create_mock_repo_commits(mongodb_mongo_dir, 2)
            try:
                # Call function to push branch to public repository, expecting an exception
                sync_repo_with_copybara.push_branch_to_destination_repo(
                    mongodb_mongo_dir,
                    sync_repo_with_copybara.CopybaraConfig(
                        source=sync_repo_with_copybara.CopybaraRepoConfig(
                            git_url="",
                            repo_name="",
                            branch="",
                        ),
                        destination=sync_repo_with_copybara.CopybaraRepoConfig(
                            git_url="",
                            repo_name="",
                            branch="",
                        ),
                    ),
                    invalid_branching_off_commit,
                )
            except Exception as err:
                if (
                    str(err)
                    == "The new branch top commit does not match the branching_off_commit. Aborting push."
                ):
                    return

            self.fail(f"{test_name}: FAIL!")


class TestReleaseTagHelpers(unittest.TestCase):
    def test_parse_release_tag_request_maps_public_branch(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_release_tag_request("r8.2.7"),
            sync_repo_with_copybara.ReleaseTagRequest(
                release_tag="r8.2.7",
                public_branch="v8.2.7",
            ),
        )

    def test_parse_release_tag_request_preserves_suffix_in_public_branch(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_release_tag_request("r8.2.7-hotfix"),
            sync_repo_with_copybara.ReleaseTagRequest(
                release_tag="r8.2.7-hotfix",
                public_branch="v8.2.7-hotfix",
            ),
        )

    def test_parse_release_tag_request_rejects_invalid_format(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.parse_release_tag_request("r8.2")

    def test_prepared_copybara_workflow_name_prefers_release_tag(self):
        self.assertEqual(
            sync_repo_with_copybara.get_prepared_copybara_workflow_name(
                "prod", "v8.2.7-hotfix", "r8.2.7-hotfix"
            ),
            "prod_r8.2.7-hotfix",
        )

    def test_prepared_copybara_workflow_name_uses_branch_without_release_tag(self):
        self.assertEqual(
            sync_repo_with_copybara.get_prepared_copybara_workflow_name("prod", "v8.2"),
            "prod_v8.2",
        )

    def test_parse_remote_tag_commit_prefers_exact_peeled_match(self):
        output = "\n".join(
            [
                "1111111111111111111111111111111111111111\trefs/tags/r8.2.70",
                "2222222222222222222222222222222222222222\trefs/tags/r8.2.7",
                "3333333333333333333333333333333333333333\trefs/tags/r8.2.7^{}",
            ]
        )

        self.assertEqual(
            sync_repo_with_copybara.parse_remote_tag_commit(output, "r8.2.7"),
            "3333333333333333333333333333333333333333",
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_tag_exists_remote_requires_exact_tag_match(self, mock_run_command):
        mock_run_command.return_value = (
            "1111111111111111111111111111111111111111\trefs/tags/r8.2.70\n"
            "2222222222222222222222222222222222222222\trefs/tags/r8.2.7-hotfix"
        )

        self.assertFalse(
            sync_repo_with_copybara.tag_exists_remote("https://example.com/public.git", "r8.2.7")
        )

    def test_resolve_requested_release_tag_branches_creates_synthetic_fragment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            branch_to_fragment = {"master": Path("master.sky")}

            requested_branches, release_requests = (
                sync_repo_with_copybara.resolve_requested_release_tag_branches(
                    requested_branches="master, r8.2.7",
                    branch_to_fragment=branch_to_fragment,
                    bundle_dir=Path(tmpdir),
                )
            )

            self.assertEqual(requested_branches, "master,v8.2.7")
            self.assertEqual(
                release_requests,
                {
                    "v8.2.7": sync_repo_with_copybara.ReleaseTagRequest(
                        release_tag="r8.2.7",
                        public_branch="v8.2.7",
                    )
                },
            )
            synthetic_fragment = branch_to_fragment["v8.2.7"]
            self.assertTrue(synthetic_fragment.is_file())
            self.assertIn('sync_tag("r8.2.7")', synthetic_fragment.read_text())

    def test_resolve_requested_release_tag_branches_preserves_suffix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            branch_to_fragment = {"master": Path("master.sky")}

            requested_branches, release_requests = (
                sync_repo_with_copybara.resolve_requested_release_tag_branches(
                    requested_branches="r8.2.7-hotfix",
                    branch_to_fragment=branch_to_fragment,
                    bundle_dir=Path(tmpdir),
                )
            )

            self.assertEqual(requested_branches, "v8.2.7-hotfix")
            self.assertEqual(
                release_requests,
                {
                    "v8.2.7-hotfix": sync_repo_with_copybara.ReleaseTagRequest(
                        release_tag="r8.2.7-hotfix",
                        public_branch="v8.2.7-hotfix",
                    )
                },
            )
            self.assertIn(
                'sync_tag("r8.2.7-hotfix")',
                branch_to_fragment["v8.2.7-hotfix"].read_text(),
            )

    def test_extract_release_tags_from_fragment_reads_sync_tag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fragment_path = Path(tmpdir) / "release_tag.sky"
            fragment_path.write_text('sync_tag("r8.2.7-hotfix")\n')

            self.assertEqual(
                sync_repo_with_copybara.extract_release_tags_from_fragment(fragment_path),
                ["r8.2.7-hotfix"],
            )

    def test_extract_branches_from_fragment_rejects_release_tag_as_branch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fragment_path = Path(tmpdir) / "bad_branch.sky"
            fragment_path.write_text('sync_branch("r8.2.7")\n')

            with self.assertRaises(SystemExit):
                sync_repo_with_copybara.extract_branches_from_fragment(fragment_path)

    def test_extract_release_tags_from_fragment_rejects_branch_as_release_tag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fragment_path = Path(tmpdir) / "bad_tag.sky"
            fragment_path.write_text('sync_tag("v8.2")\n')

            with self.assertRaises(SystemExit):
                sync_repo_with_copybara.extract_release_tags_from_fragment(fragment_path)


def write_base_copybara_config(
    path: Path,
    common_patterns: list[str] | None = None,
    common_includes: list[str] | None = None,
    source_url: str = sync_repo_with_copybara.SOURCE_REPO_URL,
    prod_url: str = sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL,
    test_url: str = sync_repo_with_copybara.TEST_REPO_URL,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if common_patterns is None:
        common_patterns = list(DEFAULT_COMMON_EXCLUDED_PATTERNS)
    if common_includes is None:
        common_includes = ["**"]

    include_entries = "\n".join(f'    "{pattern}",' for pattern in common_includes)
    exclude_entries = "\n".join(f'    "{pattern}",' for pattern in common_patterns)
    path.write_text(
        f'source_url = "{source_url}"\n'
        f'prod_url = "{prod_url}"\n'
        f'test_url = "{test_url}"\n'
        f'test_branch_prefix = "{sync_repo_with_copybara.DEFAULT_TEST_BRANCH_PREFIX}"\n'
        f'test_workflow_base_branch = ""\n'
        f'test_workflow_source_branch = ""\n'
        f"source_refs = {{}}\n"
        f"\n"
        f"common_files_to_include = [\n"
        f"{include_entries}\n"
        f"]\n"
        f"\n"
        f"common_files_to_exclude = [\n"
        f"{exclude_entries}\n"
        f"]\n"
        f"\n"
        f"def make_workflow(\n"
        f"    workflow_name,\n"
        f"    destination_url,\n"
        f"    source_ref,\n"
        f"    destination_ref,\n"
        f"):\n"
        f"    pass\n"
        f"\n"
        f"def sync_branch(branch_name):\n"
        f"    source_ref = source_refs.get(branch_name, branch_name)\n"
        f'    make_workflow("prod_" + branch_name, prod_url, source_ref, branch_name)\n'
        f"    make_workflow(\n"
        f'        "test_" + branch_name,\n'
        f"        test_url,\n"
        f"        source_ref,\n"
        f'        test_branch_prefix + "_" + branch_name,\n'
        f"    )\n"
    )


class TestSkyExclusionChecks(unittest.TestCase):
    def test_extract_sky_excluded_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)

            patterns = sync_repo_with_copybara.extract_sky_excluded_patterns(str(sky_path))

            self.assertIn("src/mongo/db/modules/**", patterns)
            self.assertIn("AGENTS.md", patterns)

    def test_extract_sky_excluded_patterns_prefers_adjacent_path_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            sky_path.write_text('common_files_to_exclude = ["ignored/**"]\n')
            write_copybara_path_rules(
                sky_path.with_name("copybara_path_rules.json"),
                common_includes=DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES,
                common_excludes=["src/authoritative/**"],
            )

            patterns = sync_repo_with_copybara.extract_sky_excluded_patterns(str(sky_path))

            self.assertEqual(patterns, {"src/authoritative/**"})

    def test_get_preview_excluded_patterns_includes_common_exclusions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_patterns=DEFAULT_COMMON_EXCLUDED_PATTERNS + ["docs/private-notes/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_branch("master")\n')

            patterns = sync_repo_with_copybara.get_preview_excluded_patterns(
                str(sky_path), "master"
            )

            self.assertIn("docs/private-notes/**", patterns)
            self.assertIn("AGENTS.md", patterns)

    def test_get_preview_excluded_patterns_includes_branch_specific_additions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(
                sky_path.read_text()
                + '\nrelease_files_to_exclude = [\n    "docs/private-notes/**",\n]\n'
                + 'sync_branch("v8.2", release_files_to_exclude)\n'
            )

            patterns = sync_repo_with_copybara.get_preview_excluded_patterns(str(sky_path), "v8.2")

            self.assertIn("docs/private-notes/**", patterns)
            self.assertIn("AGENTS.md", patterns)

    def test_get_preview_excluded_patterns_deduplicates_common_and_branch_exclusions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_patterns=["AGENTS.md", "internal/"],
            )
            sky_path.write_text(
                sky_path.read_text()
                + '\nrelease_files_to_exclude = [\n    "internal/",\n    "private/**",\n]\n'
                + 'sync_branch("v8.2", release_files_to_exclude)\n'
            )

            patterns = sync_repo_with_copybara.get_preview_excluded_patterns(str(sky_path), "v8.2")

            self.assertEqual(patterns, ["AGENTS.md", "internal/", "private/**"])

    def test_extract_branch_public_patterns_defaults_to_all_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(sky_path.read_text() + '\nsync_branch("master")\n')

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(
                str(sky_path), "master"
            )

            self.assertEqual(patterns, {"**"})

    def test_extract_branch_public_patterns_from_common_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_includes=["README.md", "docs/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_branch("master")\n')

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(
                str(sky_path), "master"
            )

            self.assertEqual(patterns, {"README.md", "docs/**"})

    def test_extract_branch_public_patterns_supports_sync_tag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_includes=["README.md", "docs/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_tag("r8.2.7")\n')

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(
                str(sky_path), "v8.2.7"
            )

            self.assertEqual(patterns, {"README.md", "docs/**"})

    def test_extract_branch_public_patterns_ignores_branch_exclusions_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_patterns=["AGENTS.md", "internal/**"],
                common_includes=["src/", "buildscripts/", "jstests/**"],
            )
            sky_path.write_text(
                sky_path.read_text()
                + '\nrelease_exclusions = [\n    "private/**",\n    "secrets/**",\n]\n'
                + 'sync_branch("v8.2", release_exclusions)\n'
            )

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(str(sky_path), "v8.2")

            self.assertEqual(patterns, {"src/", "buildscripts/", "jstests/**"})

    def test_extract_branch_public_patterns_prefers_adjacent_path_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            sky_path.write_text(
                'common_files_to_include = ["ignored/**"]\n' + '\nsync_branch("master")\n'
            )
            write_copybara_path_rules(
                sky_path.with_name("copybara_path_rules.json"),
                common_excludes=DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES,
                common_includes=["README.md", "docs/**"],
            )

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(
                str(sky_path), "master"
            )

            self.assertEqual(patterns, {"README.md", "docs/**"})

    def test_extract_branch_public_patterns_from_named_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(
                sky_path.read_text()
                + '\nmaster_public_files = [\n    "README.md",\n    "docs/**",\n]\n'
                + 'sync_branch("master", [], master_public_files)\n'
            )

            patterns = sync_repo_with_copybara.extract_branch_public_patterns(
                str(sky_path), "master"
            )

            self.assertEqual(patterns, {"README.md", "docs/**"})

    def test_check_branch_top_level_paths_are_labeled_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_includes=["README.md", "docs/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_branch("master")\n')

            sync_repo_with_copybara.check_branch_top_level_paths_are_labeled(
                str(sky_path),
                "master",
                {"README.md", "docs", "monguard", "sbom.private.json"},
            )

    def test_check_branch_top_level_paths_are_labeled_supports_sync_tag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_includes=["README.md", "docs/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_tag("r8.2.7")\n')

            sync_repo_with_copybara.check_branch_top_level_paths_are_labeled(
                str(sky_path),
                "v8.2.7",
                {"README.md", "docs", "monguard", "sbom.private.json"},
            )

    def test_check_branch_top_level_paths_are_labeled_fails_for_unlabeled_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                sky_path,
                common_includes=["README.md", "docs/**"],
            )
            sky_path.write_text(sky_path.read_text() + '\nsync_branch("master")\n')

            with self.assertRaises(SystemExit):
                sync_repo_with_copybara.check_branch_top_level_paths_are_labeled(
                    str(sky_path),
                    "master",
                    {"README.md", "docs", "src"},
                )


class TestCopybaraConfigHelpers(unittest.TestCase):
    def test_build_copybara_config_uses_test_branch_prefix(self):
        config = sync_repo_with_copybara.build_copybara_config(
            workflow="test",
            branch="v8.2",
            source_ref="deadbeef123",
            test_branch_prefix="copybara_test_branch_patch123",
        )

        self.assertEqual(config.source.branch, "v8.2")
        self.assertEqual(config.source.ref, "deadbeef123")
        self.assertEqual(config.destination.branch, "copybara_test_branch_patch123_v8.2")
        self.assertEqual(config.destination.repo_name, sync_repo_with_copybara.TEST_REPO_NAME)

    @patch("buildscripts.copybara.sync_repo_with_copybara.get_installation_access_token")
    def test_get_copybara_tokens_uses_master_sync_public_app_expansion(
        self, mock_get_installation_access_token
    ):
        expansions = {
            "app_id_copybara_syncer_master_sync": "101",
            "private_key_copybara_syncer": "public-private-key",
            "installation_id_copybara_syncer": "202",
            "app_id_copybara_syncer_10gen": "303",
            "private_key_copybara_syncer_10gen": "private-private-key",
            "installation_id_copybara_syncer_10gen": "404",
        }
        mock_get_installation_access_token.side_effect = ["public-token", "private-token"]

        tokens = sync_repo_with_copybara.get_copybara_tokens(expansions)

        self.assertEqual(
            mock_get_installation_access_token.call_args_list,
            [
                call(101, "public-private-key", 202),
                call(303, "private-private-key", 404),
            ],
        )
        self.assertEqual(
            tokens,
            {
                sync_repo_with_copybara.SOURCE_REPO_URL: "private-token",
                sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "public-token",
                sync_repo_with_copybara.TEST_REPO_URL: "private-token",
            },
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_list_copybara_fragment_paths_excludes_base_config(self, mock_run_command):
        mock_run_command.return_value = "\n".join(
            [
                sync_repo_with_copybara.COPYBARA_BASE_CONFIG_PATH.as_posix(),
                sync_repo_with_copybara.COPYBARA_PATH_RULES_MODULE_PATH.as_posix(),
                "buildscripts/copybara/master.sky",
                "buildscripts/copybara/v8_2.sky",
            ]
        )

        fragment_paths = sync_repo_with_copybara.list_copybara_fragment_paths(
            Path("/tmp/fetch"),
            sync_repo_with_copybara.COPYBARA_CONFIG_FETCH_REF,
        )

        self.assertEqual(
            fragment_paths,
            ["buildscripts/copybara/master.sky", "buildscripts/copybara/v8_2.sky"],
        )

    def test_discover_copybara_branches_reads_fragments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_base_copybara_config(get_repo_base_copybara_config_path(root))
            write_copybara_path_rules(
                get_repo_copybara_path_rules_path(root),
                common_includes=DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES,
                common_excludes=DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES,
            )
            write_copybara_path_rules_module(
                get_repo_copybara_path_rules_module_path(root),
                get_repo_copybara_path_rules_path(root),
            )
            fragment_dir = root / "buildscripts" / "copybara"
            fragment_dir.mkdir(parents=True, exist_ok=True)
            (fragment_dir / "master.sky").write_text('sync_branch("master")\n')
            (fragment_dir / "v8_2.sky").write_text(
                'sync_branch("v8.2")\n' 'sync_branch("v8.2.6-hotfix")\n'
            )
            (fragment_dir / "v8_2_7_tag.sky").write_text('sync_tag("r8.2.7")\n')

            branch_to_fragment = sync_repo_with_copybara.discover_copybara_branches(tmpdir)

            self.assertEqual(branch_to_fragment["master"], fragment_dir / "master.sky")
            self.assertEqual(branch_to_fragment["v8.2"], fragment_dir / "v8_2.sky")
            self.assertEqual(branch_to_fragment["v8.2.6-hotfix"], fragment_dir / "v8_2.sky")
            self.assertNotIn("v8.2.7", branch_to_fragment)

    def test_resolve_requested_branches_preserves_user_order(self):
        branch_to_fragment = {
            "master": Path("master.sky"),
            "v8.0": Path("v8_0.sky"),
            "v8.2": Path("v8_2.sky"),
        }

        selected = sync_repo_with_copybara.resolve_requested_branches(
            "v8.2, master, v8.2", branch_to_fragment
        )

        self.assertEqual(selected, ["v8.2", "master"])

    def test_prepare_branch_sync_for_test_workflow_generates_branch_specific_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base_config_path = get_repo_base_copybara_config_path(root)
            write_base_copybara_config(base_config_path)
            path_rules_path = get_repo_copybara_path_rules_path(root)
            write_copybara_path_rules(
                path_rules_path,
                common_includes=DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES,
                common_excludes=DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES,
            )
            path_rules_module_path = get_repo_copybara_path_rules_module_path(root)
            write_copybara_path_rules_module(path_rules_module_path, path_rules_path)
            fragment_dir = root / "buildscripts" / "copybara"
            fragment_dir.mkdir(parents=True, exist_ok=True)
            fragment_path = fragment_dir / "v8_2.sky"
            fragment_path.write_text('sync_branch("v8.2")\n')
            config_bundle = sync_repo_with_copybara.CopybaraConfigBundle(
                config_sha="configsha123",
                bundle_dir=root,
                base_config_path=base_config_path,
                path_rules_path=path_rules_path,
                path_rules_module_path=path_rules_module_path,
                branch_to_fragment={"v8.2": fragment_path},
            )
            test_baseline = sync_repo_with_copybara.TestWorkflowBaseline(
                source_last_rev="feedface123",
                destination_base_revision="publicdeadbeef456",
                public_branch="v8.2",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                prepared = sync_repo_with_copybara.prepare_branch_sync(
                    current_dir=tmpdir,
                    workflow="test",
                    branch="v8.2",
                    source_ref="deadbeef123",
                    config_bundle=config_bundle,
                    fragment_path=fragment_path,
                    tokens_map={
                        sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
                        sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
                        sync_repo_with_copybara.TEST_REPO_URL: "test-token",
                    },
                    test_branch_prefix="copybara_test_branch_patch123",
                    test_baseline=test_baseline,
                )
            log_output = stdout.getvalue()

            self.assertTrue(prepared.config_file.with_name("copybara_path_rules.json").is_file())
            self.assertTrue(
                prepared.config_file.with_name("copybara_path_rules.bara.sky").is_file()
            )

            generated_config = prepared.config_file.read_text()
            expected_test_branch = "copybara_test_branch_patch123_v8.2"

            self.assertIn('sync_branch("v8.2")', generated_config)
            self.assertIn('test_branch_prefix = "copybara_test_branch_patch123"', generated_config)
            self.assertIn(f'source_refs = {{"v8.2": "{expected_test_branch}"}}', generated_config)
            self.assertEqual(prepared.source_ref, expected_test_branch)
            self.assertEqual(prepared.config_sha, "configsha123")
            self.assertEqual(prepared.workflow_name, "test_v8.2")
            self.assertEqual(prepared.copybara_config.source.branch, expected_test_branch)
            self.assertEqual(prepared.copybara_config.source.ref, expected_test_branch)
            self.assertEqual(prepared.copybara_config.destination.branch, expected_test_branch)
            self.assertEqual(prepared.last_rev, "feedface123")
            self.assertEqual(prepared.test_baseline, test_baseline)
            self.assertEqual(
                prepared.dry_run_args,
                ("--init-history", "--last-rev=feedface123"),
            )
            self.assertIn(f"{prepared.config_file.parent}:/usr/src/app", prepared.docker_command)
            self.assertNotIn(
                f"{prepared.config_file}:/usr/src/app/copy.bara.sky", prepared.docker_command
            )
            self.assertIn("[v8.2] BEGIN generated Copybara config:", log_output)
            self.assertIn("[v8.2] BEGIN generated Copybara path rules module:", log_output)
            self.assertIn(
                'source_url = "https://x-access-token:<REDACTED>@github.com/10gen/mongo.git"',
                log_output,
            )
            self.assertIn("common_files_to_exclude = [", log_output)
            self.assertIn('"src/mongo/db/modules/**"', log_output)
            self.assertNotIn("source-token", log_output)
            self.assertNotIn("prod-token", log_output)
            self.assertNotIn("test-token", log_output)

    @patch("buildscripts.copybara.sync_repo_with_copybara.check_destination_branch_exists")
    def test_prepare_branch_sync_for_prod_workflow_uses_configured_prod_destination(
        self, mock_check_destination_branch_exists
    ):
        mock_check_destination_branch_exists.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base_config_path = get_repo_base_copybara_config_path(root)
            write_base_copybara_config(
                base_config_path,
                prod_url=sync_repo_with_copybara.TEST_REPO_URL,
            )
            path_rules_path = get_repo_copybara_path_rules_path(root)
            write_copybara_path_rules(
                path_rules_path,
                common_includes=DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES,
                common_excludes=DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES,
            )
            path_rules_module_path = get_repo_copybara_path_rules_module_path(root)
            write_copybara_path_rules_module(path_rules_module_path, path_rules_path)
            fragment_dir = root / "buildscripts" / "copybara"
            fragment_dir.mkdir(parents=True, exist_ok=True)
            fragment_path = fragment_dir / "v8_2.sky"
            fragment_path.write_text('sync_branch("v8.2")\n')
            config_bundle = sync_repo_with_copybara.CopybaraConfigBundle(
                config_sha="configsha123",
                bundle_dir=root,
                base_config_path=base_config_path,
                path_rules_path=path_rules_path,
                path_rules_module_path=path_rules_module_path,
                branch_to_fragment={"v8.2": fragment_path},
            )

            prepared = sync_repo_with_copybara.prepare_branch_sync(
                current_dir=tmpdir,
                workflow="prod",
                branch="v8.2",
                source_ref="deadbeef123",
                config_bundle=config_bundle,
                fragment_path=fragment_path,
                tokens_map={
                    sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
                    sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
                    sync_repo_with_copybara.TEST_REPO_URL: "test-token",
                },
                test_branch_prefix="copybara_test_branch_patch123",
            )

        self.assertEqual(
            prepared.copybara_config.destination.git_url,
            "https://x-access-token:test-token@github.com/10gen/mongo-copybara.git",
        )
        self.assertEqual(
            prepared.copybara_config.destination.repo_name,
            sync_repo_with_copybara.TEST_REPO_NAME,
        )
        mock_check_destination_branch_exists.assert_called_once_with(prepared.copybara_config)


class TestCopybaraConfigAndTestWorkflowHelpers(unittest.TestCase):
    def test_get_test_workflow_base_branch_override_reads_sky_variable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(
                sky_path.read_text().replace(
                    'test_workflow_base_branch = ""',
                    'test_workflow_base_branch = "  v8.2  "',
                )
            )

            self.assertEqual(
                sync_repo_with_copybara.get_test_workflow_base_branch_override(sky_path),
                "v8.2",
            )

    def test_get_test_workflow_base_branch_override_defaults_to_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)

            self.assertIsNone(
                sync_repo_with_copybara.get_test_workflow_base_branch_override(sky_path)
            )

    def test_resolve_test_workflow_requested_branches_prefers_base_branch_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(
                sky_path.read_text().replace(
                    'test_workflow_base_branch = ""',
                    'test_workflow_base_branch = "v8.2"',
                )
            )

            requested, override = sync_repo_with_copybara.resolve_test_workflow_requested_branches(
                "master",
                sky_path,
            )

            self.assertEqual(requested, "v8.2")
            self.assertEqual(override, "v8.2")

    def test_resolve_test_workflow_requested_branches_defaults_to_requested_branches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)

            requested, override = sync_repo_with_copybara.resolve_test_workflow_requested_branches(
                "master",
                sky_path,
            )

            self.assertEqual(requested, "master")
            self.assertIsNone(override)

    def test_get_test_workflow_source_branch_override_reads_sky_variable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            sky_path.write_text(
                sky_path.read_text().replace(
                    'test_workflow_source_branch = ""',
                    'test_workflow_source_branch = "  daniel.moody/8.3_test_branch  "',
                )
            )

            self.assertEqual(
                sync_repo_with_copybara.get_test_workflow_source_branch_override(sky_path),
                "daniel.moody/8.3_test_branch",
            )

    def test_get_test_workflow_source_branch_override_defaults_to_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)

            self.assertIsNone(
                sync_repo_with_copybara.get_test_workflow_source_branch_override(sky_path)
            )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_list_untracked_paths_skips_untracked_directories(self, mock_run_command):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir)
            (repo_dir / "new.txt").write_text("new")
            (repo_dir / "copybara").mkdir()
            mock_run_command.return_value = "new.txt\0copybara\0"

            untracked_paths = sync_repo_with_copybara.list_untracked_paths(repo_dir)

        self.assertEqual(untracked_paths, [Path("new.txt")])

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_list_untracked_paths_keeps_symlinked_directories(self, mock_run_command):
        if sys.platform == "win32":
            self.skipTest("symlink permissions vary on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir)
            (repo_dir / "target_dir").mkdir()
            os.symlink("target_dir", repo_dir / "linked_dir")
            mock_run_command.return_value = "linked_dir\0"

            untracked_paths = sync_repo_with_copybara.list_untracked_paths(repo_dir)

        self.assertEqual(untracked_paths, [Path("linked_dir")])

    def test_filter_untracked_paths_for_test_source_skips_task_generated_paths(self):
        filtered_paths = sync_repo_with_copybara.filter_untracked_paths_for_test_source(
            [
                Path(".evergreen.yml"),
                Path("tmp_copybara/config_bundle/copy.bara.sky"),
                Path("new.txt"),
                Path("buildscripts/new_copybara_fragment.sky"),
            ]
        )

        self.assertEqual(
            filtered_paths,
            [
                Path("new.txt"),
                Path("buildscripts/new_copybara_fragment.sky"),
            ],
        )

    def test_copy_paths_into_repo_skips_directories(self):
        with (
            tempfile.TemporaryDirectory() as source_tmpdir,
            tempfile.TemporaryDirectory() as dest_tmpdir,
        ):
            source_dir = Path(source_tmpdir)
            destination_dir = Path(dest_tmpdir)

            (source_dir / "tracked.txt").write_text("tracked")
            (source_dir / "copybara").mkdir()
            (source_dir / "copybara" / "README.md").write_text("nested repo contents")

            sync_repo_with_copybara.copy_paths_into_repo(
                source_dir,
                destination_dir,
                [Path("copybara"), Path("tracked.txt")],
            )

            self.assertFalse((destination_dir / "copybara").exists())
            self.assertEqual((destination_dir / "tracked.txt").read_text(), "tracked")

    def test_copy_paths_into_repo_preserves_symlinks(self):
        if sys.platform == "win32":
            self.skipTest("symlink permissions vary on Windows")

        with (
            tempfile.TemporaryDirectory() as source_tmpdir,
            tempfile.TemporaryDirectory() as dest_tmpdir,
        ):
            source_dir = Path(source_tmpdir)
            destination_dir = Path(dest_tmpdir)

            (source_dir / "target.txt").write_text("target")
            os.symlink("target.txt", source_dir / "linked.txt")
            (destination_dir / "linked.txt").write_text("stale")

            sync_repo_with_copybara.copy_paths_into_repo(
                source_dir,
                destination_dir,
                [Path("linked.txt")],
            )

            self.assertTrue((destination_dir / "linked.txt").is_symlink())
            self.assertEqual(os.readlink(destination_dir / "linked.txt"), "target.txt")

    def test_remove_paths_from_repo_removes_symlinks(self):
        if sys.platform == "win32":
            self.skipTest("symlink permissions vary on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir)
            (repo_dir / "target.txt").write_text("target")
            os.symlink("target.txt", repo_dir / "linked.txt")

            sync_repo_with_copybara.remove_paths_from_repo(repo_dir, [Path("linked.txt")])

            self.assertFalse((repo_dir / "linked.txt").exists())
            self.assertFalse((repo_dir / "linked.txt").is_symlink())

    @patch("buildscripts.copybara.sync_repo_with_copybara.tempfile.mkdtemp")
    @patch("buildscripts.copybara.sync_repo_with_copybara.find_matching_commit_pair")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    def test_resolve_test_workflow_baseline_uses_public_branch_when_present(
        self,
        mock_branch_exists_remote,
        mock_run_command,
        mock_find_matching_commit_pair,
        mock_mkdtemp,
    ):
        mock_branch_exists_remote.return_value = True
        public_baseline_dir = Path("/tmp/public-baseline")
        mock_mkdtemp.return_value = str(public_baseline_dir)
        mock_find_matching_commit_pair.return_value = sync_repo_with_copybara.MatchingCommit(
            source_commit="private123",
            destination_commit="public456",
        )

        baseline = sync_repo_with_copybara.resolve_test_workflow_baseline(
            current_dir="/repo",
            branch="v8.2",
            patch_base_revision="deadbeef123",
            public_repo_url="https://example.com/public.git",
        )

        self.assertEqual(
            baseline,
            sync_repo_with_copybara.TestWorkflowBaseline(
                source_last_rev="private123",
                destination_base_revision="public456",
                public_branch="v8.2",
            ),
        )
        mock_run_command.assert_called_once_with(
            "git clone --filter=blob:none --no-checkout --single-branch -b v8.2 "
            f"https://example.com/public.git {sync_repo_with_copybara.shell_quote(public_baseline_dir)}"
        )
        mock_find_matching_commit_pair.assert_called_once_with(
            "/repo",
            str(public_baseline_dir),
            source_ref="deadbeef123",
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.tempfile.mkdtemp")
    @patch("buildscripts.copybara.sync_repo_with_copybara.find_matching_commit_pair")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    def test_resolve_test_workflow_baseline_uses_source_branch_override(
        self,
        mock_branch_exists_remote,
        mock_run_command,
        mock_find_matching_commit_pair,
        mock_mkdtemp,
    ):
        mock_branch_exists_remote.return_value = True
        public_baseline_dir = Path("/tmp/public-baseline")
        private_source_dir = Path("/tmp/private-source")
        mock_mkdtemp.side_effect = [str(public_baseline_dir), str(private_source_dir)]
        mock_find_matching_commit_pair.return_value = sync_repo_with_copybara.MatchingCommit(
            source_commit="private123",
            destination_commit="public456",
        )

        baseline = sync_repo_with_copybara.resolve_test_workflow_baseline(
            current_dir="/repo",
            branch="v8.2",
            patch_base_revision="deadbeef123",
            public_repo_url="https://example.com/public.git",
            source_repo_url="https://example.com/source.git",
            test_source_branch="daniel.moody/8.3_test_branch",
        )

        self.assertEqual(
            baseline,
            sync_repo_with_copybara.TestWorkflowBaseline(
                source_last_rev="private123",
                destination_base_revision="public456",
                public_branch="v8.2",
            ),
        )
        self.assertEqual(
            mock_run_command.call_args_list[0].args[0],
            "git clone --filter=blob:none --no-checkout --single-branch -b "
            "daniel.moody/8.3_test_branch https://example.com/source.git "
            f"{sync_repo_with_copybara.shell_quote(private_source_dir)}",
        )
        self.assertEqual(
            mock_run_command.call_args_list[1].args[0],
            "git clone --filter=blob:none --no-checkout --single-branch -b v8.2 "
            f"https://example.com/public.git {sync_repo_with_copybara.shell_quote(public_baseline_dir)}",
        )
        mock_find_matching_commit_pair.assert_called_once_with(
            str(private_source_dir),
            str(public_baseline_dir),
            source_ref="HEAD",
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.tempfile.mkdtemp")
    @patch("buildscripts.copybara.sync_repo_with_copybara.find_matching_commit_pair")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    def test_resolve_test_workflow_baseline_falls_back_to_public_default_branch(
        self,
        mock_branch_exists_remote,
        mock_run_command,
        mock_find_matching_commit_pair,
        mock_mkdtemp,
    ):
        mock_branch_exists_remote.return_value = False
        public_baseline_dir = Path("/tmp/public-baseline")
        mock_mkdtemp.return_value = str(public_baseline_dir)
        mock_find_matching_commit_pair.return_value = sync_repo_with_copybara.MatchingCommit(
            source_commit="private123",
            destination_commit="public456",
        )

        baseline = sync_repo_with_copybara.resolve_test_workflow_baseline(
            current_dir="/repo",
            branch="v8.2-hotfix",
            patch_base_revision="deadbeef123",
            public_repo_url="https://example.com/public.git",
        )

        self.assertEqual(baseline.public_branch, sync_repo_with_copybara.COPYBARA_CONFIG_REF)
        mock_run_command.assert_called_once_with(
            "git clone --filter=blob:none --no-checkout --single-branch -b master "
            f"https://example.com/public.git {sync_repo_with_copybara.shell_quote(public_baseline_dir)}"
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.remove_paths_from_repo")
    @patch("buildscripts.copybara.sync_repo_with_copybara.copy_paths_into_repo")
    @patch("buildscripts.copybara.sync_repo_with_copybara.list_untracked_paths")
    @patch("buildscripts.copybara.sync_repo_with_copybara.list_changed_paths_between_refs")
    @patch("buildscripts.copybara.sync_repo_with_copybara.tempfile.mkdtemp")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_create_patched_test_source_repo_rebuilds_from_base_revision(
        self,
        mock_run_command,
        mock_mkdtemp,
        mock_list_changed_paths_between_refs,
        mock_list_untracked_paths,
        mock_copy_paths_into_repo,
        mock_remove_paths_from_repo,
    ):
        patched_source_dir = Path("/tmp/patched-source")
        mock_mkdtemp.return_value = str(patched_source_dir)
        mock_list_changed_paths_between_refs.return_value = (
            [Path("tracked.txt")],
            [Path("deleted.txt")],
        )
        mock_list_untracked_paths.return_value = [
            Path(".evergreen.yml"),
            Path("tmp_copybara/config_bundle/copy.bara.sky"),
            Path("new.txt"),
        ]
        mock_run_command.side_effect = ["", "", "", "M tracked.txt\n", ""]

        result = sync_repo_with_copybara.create_patched_test_source_repo(
            "/repo",
            "deadbeef123",
            "patch123",
        )

        self.assertEqual(result, patched_source_dir)
        mock_list_changed_paths_between_refs.assert_called_once_with("/repo", "deadbeef123")
        mock_list_untracked_paths.assert_called_once_with("/repo")
        mock_copy_paths_into_repo.assert_called_once_with(
            "/repo",
            patched_source_dir,
            [Path("new.txt"), Path("tracked.txt")],
        )
        mock_remove_paths_from_repo.assert_called_once_with(
            patched_source_dir,
            [Path("deleted.txt")],
        )
        self.assertEqual(
            mock_run_command.call_args_list[0].args[0],
            "git clone --shared --no-checkout /repo "
            f"{sync_repo_with_copybara.shell_quote(patched_source_dir)}",
        )
        self.assertEqual(
            mock_run_command.call_args_list[1].args[0],
            "git -C "
            f"{sync_repo_with_copybara.shell_quote(patched_source_dir)} "
            "checkout --detach deadbeef123",
        )
        for command_call in mock_run_command.call_args_list:
            self.assertNotIn(" apply ", command_call.args[0])

    @patch("buildscripts.copybara.sync_repo_with_copybara.tempfile.mkdtemp")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_create_test_source_repo_from_branch_clones_existing_branch(
        self,
        mock_run_command,
        mock_mkdtemp,
    ):
        source_branch_dir = Path("/tmp/source-branch")
        mock_mkdtemp.return_value = str(source_branch_dir)

        result = sync_repo_with_copybara.create_test_source_repo_from_branch(
            "https://example.com/source.git",
            "daniel.moody/8.3_test_branch",
        )

        self.assertEqual(result, source_branch_dir)
        mock_run_command.assert_called_once_with(
            "git clone --filter=blob:none --no-checkout --single-branch -b "
            "daniel.moody/8.3_test_branch https://example.com/source.git "
            f"{sync_repo_with_copybara.shell_quote(source_branch_dir)}"
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    @patch("buildscripts.copybara.sync_repo_with_copybara.push_test_destination_branch")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_patched_test_source_repo")
    @patch("buildscripts.copybara.sync_repo_with_copybara.is_current_repo_origin")
    def test_push_test_branches_pushes_clean_destination_and_patched_source(
        self,
        mock_is_current_repo_origin,
        mock_create_patched_test_source_repo,
        mock_branch_exists_remote,
        mock_push_test_destination_branch,
        mock_run_command,
    ):
        mock_is_current_repo_origin.return_value = True
        patched_source_dir = Path("/tmp/patched-source")
        mock_create_patched_test_source_repo.return_value = patched_source_dir
        mock_branch_exists_remote.return_value = True

        test_branch = "copybara_test_branch_patch123_v8.2"
        source_url = "https://example.com/source.git"
        destination_url = "https://example.com/destination.git"
        sync = sync_repo_with_copybara.PreparedBranchSync(
            branch="v8.2",
            source_ref=test_branch,
            config_sha="local",
            workflow_name="test_v8.2",
            config_file=Path("/tmp/copy.bara.sky"),
            preview_dir=Path("/tmp/preview"),
            docker_command=("echo",),
            copybara_config=sync_repo_with_copybara.CopybaraConfig(
                source=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=source_url,
                    repo_name=sync_repo_with_copybara.SOURCE_REPO_NAME,
                    branch=test_branch,
                    ref=test_branch,
                ),
                destination=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=destination_url,
                    repo_name=sync_repo_with_copybara.TEST_REPO_NAME,
                    branch=test_branch,
                ),
            ),
            last_rev="privatebase123",
            test_baseline=sync_repo_with_copybara.TestWorkflowBaseline(
                source_last_rev="privatebase123",
                destination_base_revision="publicbase456",
                public_branch="v8.2",
            ),
        )

        sync_repo_with_copybara.push_test_branches(
            "/repo",
            [sync],
            "patch123",
            patch_base_revision="deadbeef123",
            public_repo_url="https://example.com/public.git",
            source_repo_url=source_url,
        )

        mock_create_patched_test_source_repo.assert_called_once_with(
            "/repo",
            "deadbeef123",
            "patch123",
        )
        mock_push_test_destination_branch.assert_called_once_with(
            public_repo_url="https://example.com/public.git",
            public_branch="v8.2",
            destination_url=destination_url,
            destination_branch=test_branch,
            destination_base_revision="publicbase456",
        )
        mock_run_command.assert_has_calls(
            [
                call(
                    "git push "
                    f"{sync_repo_with_copybara.shell_quote(source_url)} --delete "
                    f"{sync_repo_with_copybara.shell_quote(test_branch)}"
                ),
                call(
                    "git push "
                    f"{sync_repo_with_copybara.shell_quote(destination_url)} --delete "
                    f"{sync_repo_with_copybara.shell_quote(test_branch)}"
                ),
                call(
                    f"git -C {sync_repo_with_copybara.shell_quote(patched_source_dir)} push "
                    f"{sync_repo_with_copybara.shell_quote(source_url)} "
                    f"{sync_repo_with_copybara.shell_quote(f'HEAD:refs/heads/{test_branch}')}"
                ),
            ]
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    @patch("buildscripts.copybara.sync_repo_with_copybara.push_test_destination_branch")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_test_source_repo_from_branch")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_patched_test_source_repo")
    @patch("buildscripts.copybara.sync_repo_with_copybara.is_current_repo_origin")
    def test_push_test_branches_uses_source_branch_override(
        self,
        mock_is_current_repo_origin,
        mock_create_patched_test_source_repo,
        mock_create_test_source_repo_from_branch,
        mock_branch_exists_remote,
        mock_push_test_destination_branch,
        mock_run_command,
    ):
        mock_is_current_repo_origin.return_value = True
        source_branch_dir = Path("/tmp/source-branch")
        mock_create_test_source_repo_from_branch.return_value = source_branch_dir
        mock_branch_exists_remote.return_value = True

        test_branch = "copybara_test_branch_patch123_v8.2"
        source_url = "https://example.com/source.git"
        destination_url = "https://example.com/destination.git"
        sync = sync_repo_with_copybara.PreparedBranchSync(
            branch="v8.2",
            source_ref=test_branch,
            config_sha="local",
            workflow_name="test_v8.2",
            config_file=Path("/tmp/copy.bara.sky"),
            preview_dir=Path("/tmp/preview"),
            docker_command=("echo",),
            copybara_config=sync_repo_with_copybara.CopybaraConfig(
                source=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=source_url,
                    repo_name=sync_repo_with_copybara.SOURCE_REPO_NAME,
                    branch=test_branch,
                    ref=test_branch,
                ),
                destination=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url=destination_url,
                    repo_name=sync_repo_with_copybara.TEST_REPO_NAME,
                    branch=test_branch,
                ),
            ),
            last_rev="privatebase123",
            test_baseline=sync_repo_with_copybara.TestWorkflowBaseline(
                source_last_rev="privatebase123",
                destination_base_revision="publicbase456",
                public_branch="v8.2",
            ),
        )

        sync_repo_with_copybara.push_test_branches(
            "/repo",
            [sync],
            "patch123",
            patch_base_revision="deadbeef123",
            public_repo_url="https://example.com/public.git",
            source_repo_url=source_url,
            test_source_branch="daniel.moody/8.3_test_branch",
        )

        mock_create_patched_test_source_repo.assert_not_called()
        mock_create_test_source_repo_from_branch.assert_called_once_with(
            source_url,
            "daniel.moody/8.3_test_branch",
        )
        mock_push_test_destination_branch.assert_called_once()
        self.assertEqual(
            mock_run_command.call_args_list[-1].args[0],
            f"git -C {sync_repo_with_copybara.shell_quote(source_branch_dir)} push "
            f"{sync_repo_with_copybara.shell_quote(source_url)} "
            f"{sync_repo_with_copybara.shell_quote(f'HEAD:refs/heads/{test_branch}')}",
        )


class TestMainWorkflow(unittest.TestCase):
    @patch(
        "buildscripts.copybara.sync_repo_with_copybara.ensure_generated_copybara_evergreen_is_current"
    )
    @patch("buildscripts.copybara.sync_repo_with_copybara.handle_failure")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_branch_migrate")
    @patch("buildscripts.copybara.sync_repo_with_copybara.rewrite_copybara_config")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_branch_dry_run")
    @patch("buildscripts.copybara.sync_repo_with_copybara.push_test_branches")
    @patch("buildscripts.copybara.sync_repo_with_copybara.prepare_branch_sync")
    @patch("buildscripts.copybara.sync_repo_with_copybara.resolve_test_workflow_baseline")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_test_workflow_source_branch_override")
    @patch("buildscripts.copybara.sync_repo_with_copybara.resolve_test_workflow_requested_branches")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_local_copybara_config_bundle")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_test_workflow_base_revision")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_copybara_tokens")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_mongodb_bot_gitconfig")
    @patch("buildscripts.copybara.sync_repo_with_copybara.ensure_copybara_checkout_and_image")
    @patch("buildscripts.copybara.sync_repo_with_copybara.read_config_file")
    @patch("buildscripts.copybara.sync_repo_with_copybara.os.getcwd")
    def test_main_runs_test_migration_after_successful_dry_run(
        self,
        mock_getcwd,
        mock_read_config_file,
        mock_ensure_copybara_checkout_and_image,
        mock_create_mongodb_bot_gitconfig,
        mock_get_copybara_tokens,
        mock_get_test_workflow_base_revision,
        mock_get_local_copybara_config_bundle,
        mock_resolve_test_workflow_requested_branches,
        mock_get_test_workflow_source_branch_override,
        mock_resolve_test_workflow_baseline,
        mock_prepare_branch_sync,
        mock_push_test_branches,
        mock_run_branch_dry_run,
        mock_rewrite_copybara_config,
        mock_run_branch_migrate,
        mock_handle_failure,
        mock_ensure_generated_copybara_evergreen_is_current,
    ):
        mock_read_config_file.return_value = {
            "project": sync_repo_with_copybara.EXPECTED_EVERGREEN_PROJECT,
            "version_id": "patch123",
        }
        mock_getcwd.return_value = "/repo"
        tokens = {
            sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
            sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
            sync_repo_with_copybara.TEST_REPO_URL: "test-token",
        }
        mock_get_copybara_tokens.side_effect = [tokens, tokens]
        mock_get_test_workflow_base_revision.return_value = "base123"
        mock_resolve_test_workflow_requested_branches.return_value = ("v8.2", "v8.2")
        mock_get_test_workflow_source_branch_override.return_value = "daniel.moody/v8.2_test_branch"
        test_baseline = sync_repo_with_copybara.TestWorkflowBaseline(
            source_last_rev="private123",
            destination_base_revision="public456",
            public_branch="v8.2",
        )
        mock_resolve_test_workflow_baseline.return_value = test_baseline

        with tempfile.TemporaryDirectory() as tmpdir:
            base_config_path = Path(tmpdir) / "copy.bara.sky"
            fragment_path = Path(tmpdir) / "v8_2.sky"
            write_base_copybara_config(base_config_path)
            fragment_path.write_text('sync_branch("v8.2")\n')
            mock_get_local_copybara_config_bundle.return_value = (
                sync_repo_with_copybara.CopybaraConfigBundle(
                    config_sha="local",
                    bundle_dir=Path(tmpdir),
                    base_config_path=base_config_path,
                    path_rules_path=Path(tmpdir) / "copybara_path_rules.json",
                    path_rules_module_path=Path(tmpdir) / "copybara_path_rules.bara.sky",
                    branch_to_fragment={"v8.2": fragment_path},
                )
            )
            prepared_sync = sync_repo_with_copybara.PreparedBranchSync(
                branch="v8.2",
                source_ref="copybara_test_branch_patch123_v8.2",
                config_sha="local",
                workflow_name="test_v8.2",
                config_file=Path(tmpdir) / "generated.sky",
                preview_dir=Path(tmpdir) / "preview",
                docker_command=("echo",),
                copybara_config=sync_repo_with_copybara.CopybaraConfig(
                    source=sync_repo_with_copybara.CopybaraRepoConfig(
                        git_url="https://example.com/source.git",
                        repo_name=sync_repo_with_copybara.SOURCE_REPO_NAME,
                        branch="copybara_test_branch_patch123_v8.2",
                        ref="copybara_test_branch_patch123_v8.2",
                    ),
                    destination=sync_repo_with_copybara.CopybaraRepoConfig(
                        git_url="https://example.com/destination.git",
                        repo_name=sync_repo_with_copybara.TEST_REPO_NAME,
                        branch="copybara_test_branch_patch123_v8.2",
                    ),
                ),
                last_rev="private123",
                test_baseline=test_baseline,
            )
            mock_prepare_branch_sync.return_value = prepared_sync
            mock_run_branch_dry_run.return_value = sync_repo_with_copybara.BranchDryRunResult(
                branch="v8.2"
            )

            argv = ["buildscripts/copybara/sync_repo_with_copybara.py", "--workflow=test"]
            with patch.object(sys, "argv", argv):
                sync_repo_with_copybara.main()

        mock_prepare_branch_sync.assert_called_once_with(
            current_dir="/repo",
            workflow="test",
            branch="v8.2",
            source_ref="private123",
            config_bundle=mock_get_local_copybara_config_bundle.return_value,
            fragment_path=fragment_path,
            tokens_map=tokens,
            test_branch_prefix="copybara_test_branch_patch123",
            test_baseline=test_baseline,
            expansions=mock_read_config_file.return_value,
            release_tag=None,
            release_source_commit=None,
        )
        mock_push_test_branches.assert_called_once()
        mock_ensure_generated_copybara_evergreen_is_current.assert_called_once_with(Path(tmpdir))
        mock_run_branch_dry_run.assert_called_once_with(prepared_sync)
        mock_rewrite_copybara_config.assert_called_once_with(prepared_sync.config_file, tokens)
        mock_run_branch_migrate.assert_called_once_with(prepared_sync)
        mock_handle_failure.assert_not_called()

    @patch(
        "buildscripts.copybara.sync_repo_with_copybara.ensure_generated_copybara_evergreen_is_current"
    )
    @patch("buildscripts.copybara.sync_repo_with_copybara.publish_release_tag")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_branch_migrate")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_branch_dry_run")
    @patch("buildscripts.copybara.sync_repo_with_copybara.prepare_branch_sync")
    @patch("buildscripts.copybara.sync_repo_with_copybara.activate_new_hotfix_tasks")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_remote_tag_commit")
    @patch("buildscripts.copybara.sync_repo_with_copybara.tag_exists_remote")
    @patch("buildscripts.copybara.sync_repo_with_copybara.fetch_remote_copybara_config_bundle")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_copybara_tokens")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_mongodb_bot_gitconfig")
    @patch("buildscripts.copybara.sync_repo_with_copybara.ensure_copybara_checkout_and_image")
    @patch("buildscripts.copybara.sync_repo_with_copybara.read_config_file")
    @patch("buildscripts.copybara.sync_repo_with_copybara.os.getcwd")
    def test_main_runs_prod_release_tag_sync_and_publishes_tag(
        self,
        mock_getcwd,
        mock_read_config_file,
        mock_ensure_copybara_checkout_and_image,
        mock_create_mongodb_bot_gitconfig,
        mock_get_copybara_tokens,
        mock_fetch_remote_copybara_config_bundle,
        mock_tag_exists_remote,
        mock_get_remote_tag_commit,
        mock_activate_new_hotfix_tasks,
        mock_prepare_branch_sync,
        mock_run_branch_dry_run,
        mock_run_branch_migrate,
        mock_publish_release_tag,
        mock_ensure_generated_copybara_evergreen_is_current,
    ):
        mock_read_config_file.return_value = {
            "project": sync_repo_with_copybara.EXPECTED_EVERGREEN_PROJECT,
        }
        mock_getcwd.return_value = "/repo"
        tokens = {
            sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
            sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
            sync_repo_with_copybara.TEST_REPO_URL: "test-token",
        }
        mock_get_copybara_tokens.side_effect = [tokens, tokens]
        mock_tag_exists_remote.return_value = False
        mock_get_remote_tag_commit.return_value = "tagsha123"
        synthetic_fragment_contents = ""

        with tempfile.TemporaryDirectory() as tmpdir:
            base_config_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                base_config_path,
                prod_url=sync_repo_with_copybara.TEST_REPO_URL,
            )
            fragment_path = Path(tmpdir) / "master.sky"
            fragment_path.write_text('sync_branch("master")\n')
            mock_fetch_remote_copybara_config_bundle.return_value = (
                sync_repo_with_copybara.CopybaraConfigBundle(
                    config_sha="configsha123",
                    bundle_dir=Path(tmpdir),
                    base_config_path=base_config_path,
                    path_rules_path=Path(tmpdir) / "copybara_path_rules.json",
                    path_rules_module_path=Path(tmpdir) / "copybara_path_rules.bara.sky",
                    branch_to_fragment={"master": fragment_path},
                )
            )
            prepared_sync = sync_repo_with_copybara.PreparedBranchSync(
                branch="v8.2.7",
                source_ref="tagsha123",
                config_sha="configsha123",
                workflow_name="prod_r8.2.7",
                config_file=Path("/tmp/generated.sky"),
                preview_dir=Path("/tmp/preview"),
                docker_command=("echo",),
                release_tag="r8.2.7",
                release_source_commit="tagsha123",
            )
            mock_prepare_branch_sync.return_value = prepared_sync
            mock_run_branch_dry_run.return_value = sync_repo_with_copybara.BranchDryRunResult(
                branch="v8.2.7",
                noop=True,
            )

            argv = [
                "buildscripts/copybara/sync_repo_with_copybara.py",
                "--workflow=prod",
                "--branches=r8.2.7",
            ]
            with patch.object(sys, "argv", argv):
                sync_repo_with_copybara.main()
            synthetic_fragment_contents = mock_prepare_branch_sync.call_args.kwargs[
                "fragment_path"
            ].read_text()

        prepare_call = mock_prepare_branch_sync.call_args.kwargs
        self.assertEqual(prepare_call["branch"], "v8.2.7")
        self.assertEqual(prepare_call["source_ref"], "tagsha123")
        self.assertEqual(prepare_call["release_tag"], "r8.2.7")
        self.assertEqual(prepare_call["release_source_commit"], "tagsha123")
        self.assertIn('sync_tag("r8.2.7")', synthetic_fragment_contents)
        mock_ensure_generated_copybara_evergreen_is_current.assert_called_once_with(Path(tmpdir))
        mock_run_branch_migrate.assert_not_called()
        mock_publish_release_tag.assert_called_once_with(prepared_sync, tokens)
        mock_activate_new_hotfix_tasks.assert_called_once()
        mock_tag_exists_remote.assert_called_once_with(
            "https://x-access-token:test-token@github.com/10gen/mongo-copybara.git",
            "r8.2.7",
        )

    @patch(
        "buildscripts.copybara.sync_repo_with_copybara.ensure_generated_copybara_evergreen_is_current"
    )
    @patch("buildscripts.copybara.sync_repo_with_copybara.prepare_branch_sync")
    @patch("buildscripts.copybara.sync_repo_with_copybara.tag_exists_remote")
    @patch("buildscripts.copybara.sync_repo_with_copybara.fetch_remote_copybara_config_bundle")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_copybara_tokens")
    @patch("buildscripts.copybara.sync_repo_with_copybara.create_mongodb_bot_gitconfig")
    @patch("buildscripts.copybara.sync_repo_with_copybara.ensure_copybara_checkout_and_image")
    @patch("buildscripts.copybara.sync_repo_with_copybara.read_config_file")
    @patch("buildscripts.copybara.sync_repo_with_copybara.os.getcwd")
    def test_main_rejects_existing_public_release_tag(
        self,
        mock_getcwd,
        mock_read_config_file,
        mock_ensure_copybara_checkout_and_image,
        mock_create_mongodb_bot_gitconfig,
        mock_get_copybara_tokens,
        mock_fetch_remote_copybara_config_bundle,
        mock_tag_exists_remote,
        mock_prepare_branch_sync,
        mock_ensure_generated_copybara_evergreen_is_current,
    ):
        mock_read_config_file.return_value = {
            "project": sync_repo_with_copybara.EXPECTED_EVERGREEN_PROJECT,
        }
        mock_getcwd.return_value = "/repo"
        tokens = {
            sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
            sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
            sync_repo_with_copybara.TEST_REPO_URL: "test-token",
        }
        mock_get_copybara_tokens.return_value = tokens
        mock_tag_exists_remote.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            base_config_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                base_config_path,
                prod_url=sync_repo_with_copybara.TEST_REPO_URL,
            )
            fragment_path = Path(tmpdir) / "master.sky"
            fragment_path.write_text('sync_branch("master")\n')
            mock_fetch_remote_copybara_config_bundle.return_value = (
                sync_repo_with_copybara.CopybaraConfigBundle(
                    config_sha="configsha123",
                    bundle_dir=Path(tmpdir),
                    base_config_path=base_config_path,
                    path_rules_path=Path(tmpdir) / "copybara_path_rules.json",
                    path_rules_module_path=Path(tmpdir) / "copybara_path_rules.bara.sky",
                    branch_to_fragment={"master": fragment_path},
                )
            )

            argv = [
                "buildscripts/copybara/sync_repo_with_copybara.py",
                "--workflow=prod",
                "--branches=r8.2.7",
            ]
            with patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit):
                    sync_repo_with_copybara.main()

        mock_prepare_branch_sync.assert_not_called()
        mock_ensure_generated_copybara_evergreen_is_current.assert_called_once_with(Path(tmpdir))
        mock_tag_exists_remote.assert_called_once_with(
            "https://x-access-token:test-token@github.com/10gen/mongo-copybara.git",
            "r8.2.7",
        )

    def test_rewrite_copybara_config_refreshes_existing_tokens_and_prefix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "copy.bara.sky"
            config_path.write_text(
                'source_url = "https://x-access-token:old@github.com/10gen/mongo.git"\n'
                'prod_url = "https://github.com/mongodb/mongo.git"\n'
                'test_url = "https://x-access-token:old@github.com/10gen/mongo-copybara.git"\n'
                'test_branch_prefix = "copybara_test_branch"\n'
                "\n"
                "def make_workflow(workflow_name, destination_url, source_ref, destination_ref, branch_excluded_files):\n"
                "    pass\n"
                "\n"
                "def sync_branch(branch_name, branch_excluded_files = []):\n"
                '    make_workflow("prod_" + branch_name, prod_url, branch_name, branch_name, branch_excluded_files)\n'
                "    make_workflow(\n"
                '        "test_" + branch_name,\n'
                "        test_url,\n"
                "        branch_name,\n"
                '        test_branch_prefix + "_" + branch_name,\n'
                "        branch_excluded_files,\n"
                "    )\n"
            )

            sync_repo_with_copybara.rewrite_copybara_config(
                config_file=config_path,
                tokens_map={
                    sync_repo_with_copybara.SOURCE_REPO_URL: "new-source-token",
                    sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "new-prod-token",
                    sync_repo_with_copybara.TEST_REPO_URL: "new-test-token",
                },
                test_branch_prefix="copybara_test_branch_patch456",
                source_refs={"v8.2": "deadbeef123"},
            )

            rewritten = config_path.read_text()
            self.assertIn(
                "https://x-access-token:new-source-token@github.com/10gen/mongo.git",
                rewritten,
            )
            self.assertIn(
                "https://x-access-token:new-prod-token@github.com/mongodb/mongo.git",
                rewritten,
            )
            self.assertIn(
                "https://x-access-token:new-test-token@github.com/10gen/mongo-copybara.git",
                rewritten,
            )
            self.assertIn('test_branch_prefix = "copybara_test_branch_patch456"', rewritten)
            self.assertIn('source_refs = {"v8.2": "deadbeef123"}', rewritten)
            self.assertIn("source_ref = source_refs.get(branch_name, branch_name)", rewritten)

    @patch("buildscripts.copybara.sync_repo_with_copybara.validate_preview_exclusions")
    @patch("buildscripts.copybara.sync_repo_with_copybara.validate_sync_config")
    @patch("buildscripts.copybara.sync_repo_with_copybara.rewrite_copybara_config")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_copybara_tokens")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_run_branch_dry_run_refreshes_tokens_on_auth_failure(
        self,
        mock_run_command,
        mock_get_copybara_tokens,
        mock_rewrite_copybara_config,
        mock_validate_sync_config,
        mock_validate_preview_exclusions,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            preview_dir = Path(tmpdir) / "preview"
            preview_dir.mkdir()
            stale_file = preview_dir / "stale.txt"
            stale_file.write_text("stale")
            sync = sync_repo_with_copybara.PreparedBranchSync(
                branch="v8.2",
                source_ref="deadbeef123",
                config_sha="local",
                workflow_name="prod_v8.2",
                config_file=Path(tmpdir) / "copy.bara.sky",
                preview_dir=preview_dir,
                docker_command=("echo", "copybara"),
                expansions={"version_id": "patch123"},
            )
            auth_error = subprocess.CalledProcessError(
                128,
                "copybara",
                output=(
                    "remote: Invalid username or token. Password authentication is not supported "
                    "for Git operations.\n"
                    "fatal: Authentication failed for 'https://github.com/10gen/mongo-copybara.git/'"
                ),
            )
            mock_run_command.side_effect = [auth_error, ""]
            refreshed_tokens = {
                sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
                sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
                sync_repo_with_copybara.TEST_REPO_URL: "test-token",
            }
            mock_get_copybara_tokens.return_value = refreshed_tokens

            result = sync_repo_with_copybara.run_branch_dry_run(sync)

            self.assertEqual(result, sync_repo_with_copybara.BranchDryRunResult(branch="v8.2"))
            self.assertFalse(stale_file.exists())
            self.assertEqual(mock_run_command.call_count, 2)
            mock_get_copybara_tokens.assert_called_once_with(sync.expansions)
            mock_rewrite_copybara_config.assert_called_once_with(sync.config_file, refreshed_tokens)
            mock_validate_sync_config.assert_called()
            mock_validate_preview_exclusions.assert_called_once_with(sync)

    @patch("buildscripts.copybara.sync_repo_with_copybara.rewrite_copybara_config")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_copybara_tokens")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_run_branch_migrate_refreshes_tokens_on_auth_failure(
        self,
        mock_run_command,
        mock_get_copybara_tokens,
        mock_rewrite_copybara_config,
    ):
        sync = sync_repo_with_copybara.PreparedBranchSync(
            branch="v8.2",
            source_ref="deadbeef123",
            config_sha="local",
            workflow_name="prod_v8.2",
            config_file=Path("/tmp/copy.bara.sky"),
            preview_dir=Path("/tmp/preview"),
            docker_command=("echo", "copybara"),
            expansions={"version_id": "patch123"},
        )
        auth_error = subprocess.CalledProcessError(
            128,
            "copybara",
            output=(
                "remote: Invalid username or token. Password authentication is not supported "
                "for Git operations.\n"
                "fatal: Authentication failed for 'https://github.com/10gen/mongo-copybara.git/'"
            ),
        )
        mock_run_command.side_effect = [auth_error, ""]
        refreshed_tokens = {
            sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
            sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
            sync_repo_with_copybara.TEST_REPO_URL: "test-token",
        }
        mock_get_copybara_tokens.return_value = refreshed_tokens

        sync_repo_with_copybara.run_branch_migrate(sync)

        self.assertEqual(mock_run_command.call_count, 2)
        mock_get_copybara_tokens.assert_called_once_with(sync.expansions)
        mock_rewrite_copybara_config.assert_called_once_with(sync.config_file, refreshed_tokens)

    @patch("buildscripts.copybara.sync_repo_with_copybara.get_remote_branch_head")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_fetch_remote_copybara_config_bundle_reads_latest_master_bundle(
        self, mock_run_command, mock_get_remote_branch_head
    ):
        mock_get_remote_branch_head.return_value = "configsha123"
        local_runner_contents = Path(sync_repo_with_copybara.__file__).resolve().read_text()
        local_path_rules_contents = (
            Path(sync_repo_with_copybara.__file__).resolve().with_name("path_rules.py").read_text()
        )
        template_text = (
            "rendered_from_template = True\n"
            "common_files_to_include = [\n"
            "{{COMMON_FILES_TO_INCLUDE}}\n"
            "]\n"
            "\n"
            "common_files_to_exclude = [\n"
            "{{COMMON_FILES_TO_EXCLUDE}}\n"
            "]\n"
        )

        def run_command_side_effect(command, **kwargs):
            if command.startswith("git init "):
                return ""
            if "fetch --depth 1" in command:
                return ""
            if f"rev-parse {sync_repo_with_copybara.COPYBARA_CONFIG_FETCH_REF}" in command:
                return "configsha123\n"
            if sync_repo_with_copybara.COPYBARA_SYNC_RUNNER_PATH.as_posix() in command:
                return local_runner_contents
            if sync_repo_with_copybara.COPYBARA_PATH_RULES_HELPER_PATH.as_posix() in command:
                return local_path_rules_contents
            if "ls-tree -r --name-only" in command:
                return "\n".join(
                    [
                        sync_repo_with_copybara.COPYBARA_BASE_CONFIG_PATH.as_posix(),
                        "buildscripts/copybara/master.sky",
                        "buildscripts/copybara/v8_2.sky",
                    ]
                )
            if sync_repo_with_copybara.COPYBARA_BASE_CONFIG_PATH.as_posix() in command:
                return (
                    'source_url = "https://github.com/10gen/mongo.git"\n'
                    'prod_url = "https://github.com/mongodb/mongo.git"\n'
                    'test_url = "https://github.com/10gen/mongo-copybara.git"\n'
                    'test_branch_prefix = "copybara_test_branch"\n'
                    "source_refs = {}\n"
                    "\n"
                    "def make_workflow(workflow_name, destination_url, source_ref, destination_ref, branch_excluded_files):\n"
                    "    pass\n"
                    "\n"
                    "def sync_branch(branch_name, branch_excluded_files = []):\n"
                    '    make_workflow("prod_" + branch_name, prod_url, branch_name, branch_name, branch_excluded_files)\n'
                    "    make_workflow(\n"
                    '        "test_" + branch_name,\n'
                    "        test_url,\n"
                    "        branch_name,\n"
                    '        test_branch_prefix + "_" + branch_name,\n'
                    "        branch_excluded_files,\n"
                    "    )\n"
                )
            if sync_repo_with_copybara.COPYBARA_PATH_RULES_PATH.as_posix() in command:
                return json.dumps(
                    {
                        "common_files_to_include": ["**"],
                        "common_files_to_exclude": ["src/mongo/db/modules/**"],
                    }
                )
            if sync_repo_with_copybara.COPYBARA_PATH_RULES_TEMPLATE_PATH.as_posix() in command:
                return template_text
            if (
                sync_repo_with_copybara.COPYBARA_GENERATED_EVERGREEN_CONFIG_PATH.as_posix()
                in command
            ):
                return "generated Copybara Evergreen YAML\n"
            if "buildscripts/copybara/master.sky" in command:
                return 'sync_branch("master")\n'
            if "buildscripts/copybara/v8_2.sky" in command:
                return 'sync_branch("v8.2")\n'
            raise AssertionError(f"Unexpected command: {command}")

        mock_run_command.side_effect = run_command_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = sync_repo_with_copybara.fetch_remote_copybara_config_bundle(
                tmpdir,
                "https://x-access-token:token@github.com/10gen/mongo.git",
            )

            self.assertEqual(bundle.config_sha, "configsha123")
            self.assertEqual(
                bundle.base_config_path.read_text().splitlines()[0],
                'source_url = "https://github.com/10gen/mongo.git"',
            )
            self.assertEqual(
                bundle.path_rules_path.read_text(),
                json.dumps(
                    {
                        "common_files_to_include": ["**"],
                        "common_files_to_exclude": ["src/mongo/db/modules/**"],
                    }
                ),
            )
            self.assertIn(
                "rendered_from_template = True",
                bundle.path_rules_module_path.read_text(),
            )
            generated_evergreen_config_path = (
                bundle.bundle_dir / sync_repo_with_copybara.COPYBARA_GENERATED_EVERGREEN_CONFIG_PATH
            )
            self.assertEqual(
                generated_evergreen_config_path.read_text(),
                "generated Copybara Evergreen YAML\n",
            )
            self.assertIn('"src/mongo/db/modules/**"', bundle.path_rules_module_path.read_text())
            self.assertIn("master", bundle.branch_to_fragment)
            self.assertIn("v8.2", bundle.branch_to_fragment)

    @patch("buildscripts.copybara.sync_repo_with_copybara.get_remote_branch_head")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_fetch_remote_copybara_config_bundle_fails_for_stale_checked_out_runner(
        self, mock_run_command, mock_get_remote_branch_head
    ):
        mock_get_remote_branch_head.return_value = "configsha123"

        def run_command_side_effect(command, **kwargs):
            if command.startswith("git init "):
                return ""
            if "fetch --depth 1" in command:
                return ""
            if f"rev-parse {sync_repo_with_copybara.COPYBARA_CONFIG_FETCH_REF}" in command:
                return "configsha123\n"
            if sync_repo_with_copybara.COPYBARA_SYNC_RUNNER_PATH.as_posix() in command:
                return "# stale runner from old build\n"
            raise AssertionError(f"Unexpected command: {command}")

        mock_run_command.side_effect = run_command_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                with self.assertRaises(SystemExit):
                    sync_repo_with_copybara.fetch_remote_copybara_config_bundle(
                        tmpdir,
                        "https://x-access-token:token@github.com/10gen/mongo.git",
                    )

        log_output = stdout.getvalue()
        self.assertIn("latest master-owned", log_output)
        self.assertIn(sync_repo_with_copybara.COPYBARA_SYNC_RUNNER_PATH.as_posix(), log_output)
        self.assertIn("Start a new master build", log_output)

    @patch("buildscripts.copybara.sync_repo_with_copybara.get_remote_branch_head")
    @patch("buildscripts.copybara.sync_repo_with_copybara.run_command")
    def test_fetch_remote_copybara_config_bundle_fails_for_stale_checked_out_path_rules(
        self, mock_run_command, mock_get_remote_branch_head
    ):
        mock_get_remote_branch_head.return_value = "configsha123"
        local_runner_contents = Path(sync_repo_with_copybara.__file__).resolve().read_text()

        def run_command_side_effect(command, **kwargs):
            if command.startswith("git init "):
                return ""
            if "fetch --depth 1" in command:
                return ""
            if f"rev-parse {sync_repo_with_copybara.COPYBARA_CONFIG_FETCH_REF}" in command:
                return "configsha123\n"
            if sync_repo_with_copybara.COPYBARA_SYNC_RUNNER_PATH.as_posix() in command:
                return local_runner_contents
            if sync_repo_with_copybara.COPYBARA_PATH_RULES_HELPER_PATH.as_posix() in command:
                return "# stale path rules helper from old build\n"
            raise AssertionError(f"Unexpected command: {command}")

        mock_run_command.side_effect = run_command_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                with self.assertRaises(SystemExit):
                    sync_repo_with_copybara.fetch_remote_copybara_config_bundle(
                        tmpdir,
                        "https://x-access-token:token@github.com/10gen/mongo.git",
                    )

        log_output = stdout.getvalue()
        self.assertIn("latest master-owned", log_output)
        self.assertIn(
            sync_repo_with_copybara.COPYBARA_PATH_RULES_HELPER_PATH.as_posix(), log_output
        )
        self.assertIn("path rules helper", log_output)
        self.assertIn("Start a new master build", log_output)

    def test_get_local_copybara_config_bundle_renders_checked_out_path_rules_module(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base_config_path = get_repo_base_copybara_config_path(root)
            write_base_copybara_config(base_config_path)
            path_rules_path = get_repo_copybara_path_rules_path(root)
            write_copybara_path_rules(
                path_rules_path,
                common_includes=DEFAULT_TEST_COPYBARA_PATH_RULES_INCLUDES,
                common_excludes=DEFAULT_TEST_COPYBARA_PATH_RULES_EXCLUDES,
            )
            path_rules_template_path = get_repo_copybara_path_rules_template_path(root)
            write_copybara_path_rules_template(path_rules_template_path)
            path_rules_module_path = get_repo_copybara_path_rules_module_path(root)
            fragment_dir = root / "buildscripts" / "copybara"
            fragment_dir.mkdir(parents=True, exist_ok=True)
            (fragment_dir / "master.sky").write_text('sync_branch("master")\n')
            (fragment_dir / "v8_2.sky").write_text('sync_branch("v8.2")\n')

            bundle = sync_repo_with_copybara.get_local_copybara_config_bundle(tmpdir)

            self.assertEqual(bundle.config_sha, "local")
            self.assertEqual(bundle.base_config_path, base_config_path)
            self.assertEqual(bundle.path_rules_path, path_rules_path)
            self.assertEqual(bundle.path_rules_module_path, path_rules_module_path)
            self.assertEqual(
                path_rules_module_path.read_text(),
                render_copybara_path_rules_module_from_files(
                    path_rules_template_path,
                    path_rules_path,
                ),
            )
            self.assertEqual(bundle.branch_to_fragment["master"], fragment_dir / "master.sky")
            self.assertEqual(bundle.branch_to_fragment["v8.2"], fragment_dir / "v8_2.sky")


class TestGenerateCopybaraEvergreen(unittest.TestCase):
    @staticmethod
    def write_fragment(root: Path, filename: str, contents: str) -> None:
        fragment_path = root / sync_repo_with_copybara.COPYBARA_CONFIG_DIRECTORY / filename
        fragment_path.parent.mkdir(parents=True, exist_ok=True)
        fragment_path.write_text(contents)

    def test_render_expected_copybara_evergreen_uses_branch_and_tag_fragments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_fragment(root, "master.sky", 'sync_branch("master")\n')
            self.write_fragment(
                root,
                "v8_2.sky",
                'sync_branch("v8.2")\n'
                'sync_branch("v8.2.7-hotfix")\n'
                'sync_tag("r8.2.7-hotfix")\n',
            )

            generated = generate_evergreen.render_expected_copybara_evergreen(root)

            self.assertIn(
                "# This file is generated by buildscripts/copybara/generate_evergreen.py.",
                generated,
            )
            self.assertIn("  - name: sync_copybara_master", generated)
            self.assertIn("  - name: sync_copybara_v8_2", generated)
            self.assertIn("  - name: sync_copybara_v8_2_7_hotfix", generated)
            self.assertIn('          copybara_branches: "v8.2.7-hotfix"', generated)
            self.assertIn("  - name: sync_copybara_r8_2_7_hotfix", generated)
            self.assertIn('          copybara_branches: "r8.2.7-hotfix"', generated)
            self.assertNotIn("sync_copybara_task_template", generated)
            self.assertLess(
                generated.index("sync_copybara_master"),
                generated.index("sync_copybara_v8_2"),
            )
            self.assertLess(
                generated.index("sync_copybara_v8_2_7_hotfix"),
                generated.index("sync_copybara_r8_2_7_hotfix"),
            )

    def test_check_generated_copybara_evergreen_detects_stale_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_fragment(root, "master.sky", 'sync_branch("master")\n')
            generated_path = root / generate_evergreen.COPYBARA_EVERGREEN_GENERATED_CONFIG_PATH
            generated_path.parent.mkdir(parents=True, exist_ok=True)
            generated_path.write_text("stale\n")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                is_current = generate_evergreen.check_generated_copybara_evergreen(root)

            self.assertFalse(is_current)
            self.assertIn("Generated Copybara Evergreen config is stale", stdout.getvalue())

    def test_check_generated_copybara_evergreen_accepts_current_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_fragment(root, "master.sky", 'sync_branch("master")\n')
            generated_path = root / generate_evergreen.COPYBARA_EVERGREEN_GENERATED_CONFIG_PATH
            generated_path.parent.mkdir(parents=True, exist_ok=True)
            generated_path.write_text(generate_evergreen.render_expected_copybara_evergreen(root))

            self.assertTrue(generate_evergreen.check_generated_copybara_evergreen(root))

    @patch("buildscripts.copybara.generate_evergreen.check_generated_copybara_evergreen")
    def test_sync_precheck_accepts_current_generated_evergreen(self, mock_check_generated):
        mock_check_generated.return_value = True

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            sync_repo_with_copybara.ensure_generated_copybara_evergreen_is_current("/repo")

        mock_check_generated.assert_called_once_with(Path("/repo"))
        self.assertIn("Generated Copybara Evergreen config is current", stdout.getvalue())

    @patch("buildscripts.copybara.generate_evergreen.check_generated_copybara_evergreen")
    def test_sync_precheck_rejects_stale_generated_evergreen(self, mock_check_generated):
        mock_check_generated.return_value = False

        with self.assertRaises(SystemExit) as context:
            sync_repo_with_copybara.ensure_generated_copybara_evergreen_is_current("/repo")

        self.assertEqual(context.exception.code, 1)
        mock_check_generated.assert_called_once_with(Path("/repo"))


class TestValidateSyncConfig(unittest.TestCase):
    @patch("buildscripts.copybara.sync_repo_with_copybara.check_branch_top_level_paths_are_labeled")
    @patch("buildscripts.copybara.sync_repo_with_copybara.list_top_level_paths_for_remote_ref")
    def test_uses_pinned_source_ref_for_top_level_validation(
        self,
        mock_list_top_level_paths_for_remote_ref,
        mock_check_branch_top_level_paths_are_labeled,
    ):
        mock_list_top_level_paths_for_remote_ref.return_value = {"README.md", "src"}
        sync = sync_repo_with_copybara.PreparedBranchSync(
            branch="v8.2",
            source_ref="deadbeef123",
            config_sha="configsha123",
            workflow_name="prod_v8.2",
            config_file=Path("/tmp/generated.sky"),
            preview_dir=Path("/tmp/preview"),
            docker_command=("echo", "copybara"),
            copybara_config=sync_repo_with_copybara.CopybaraConfig(
                source=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url="https://example.com/source.git",
                    repo_name=sync_repo_with_copybara.SOURCE_REPO_NAME,
                    branch="v8.2",
                    ref="deadbeef123",
                ),
                destination=sync_repo_with_copybara.CopybaraRepoConfig(
                    git_url="https://example.com/destination.git",
                    repo_name=sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_NAME,
                    branch="v8.2",
                ),
            ),
        )

        sync_repo_with_copybara.validate_sync_config(sync)

        mock_list_top_level_paths_for_remote_ref.assert_called_once_with(
            "https://example.com/source.git",
            "deadbeef123",
        )
        mock_check_branch_top_level_paths_are_labeled.assert_called_once_with(
            str(sync.config_file),
            "v8.2",
            {"README.md", "src"},
        )


class TestEnsureCopybaraSourceRefSupport(unittest.TestCase):
    """Verify that ensure_copybara_source_ref_support correctly injects or preserves source_refs."""

    def _make_config_without_source_refs(self) -> str:
        return textwrap.dedent("""\
            source_url = "https://github.com/10gen/mongo.git"
            test_branch_prefix = "copybara_test_branch"

            def sync_branch(branch_name):
                make_workflow("prod_" + branch_name, prod_url, branch_name, branch_name)
                make_workflow(
                    "test_" + branch_name,
                    test_url,
                    branch_name,
                    test_branch_prefix + "_" + branch_name,
                )
            """)

    def _make_config_with_source_refs(self) -> str:
        return textwrap.dedent("""\
            source_url = "https://github.com/10gen/mongo.git"
            test_branch_prefix = "copybara_test_branch"
            source_refs = {}

            def sync_branch(branch_name):
                source_ref = source_refs.get(branch_name, branch_name)
                make_workflow(
                    "prod_" + branch_name,
                    prod_url,
                    source_ref,
                    branch_name,
                )
                make_workflow(
                    "test_" + branch_name,
                    test_url,
                    source_ref,
                    test_branch_prefix + "_" + branch_name,
                )
            """)

    def _make_legacy_config_with_source_refs(self) -> str:
        return textwrap.dedent("""\
            source_url = "https://github.com/10gen/mongo.git"
            test_branch_prefix = "copybara_test_branch"
            source_refs = {}

            def sync_branch(branch_name, branch_excluded_files = [], branch_public_files = ["**"]):
                source_ref = source_refs.get(branch_name, branch_name)
                make_workflow(
                    "prod_" + branch_name,
                    prod_url,
                    source_ref,
                    branch_name,
                    branch_excluded_files,
                    branch_public_files,
                )
                make_workflow(
                    "test_" + branch_name,
                    test_url,
                    source_ref,
                    test_branch_prefix + "_" + branch_name,
                    branch_excluded_files,
                    branch_public_files,
                )
            """)

    def test_injects_source_refs_when_missing(self):
        contents = self._make_config_without_source_refs()
        result = sync_repo_with_copybara.ensure_copybara_source_ref_support(
            contents, Path("test.sky")
        )
        self.assertIn("source_refs = {}", result)
        self.assertIn("source_ref = source_refs.get(branch_name, branch_name)", result)
        self.assertIn("def sync_tag(tag_name):", result)
        self.assertIn(
            'make_workflow("prod_" + branch_name, prod_url, source_ref, branch_name)',
            result,
        )
        self.assertIn(
            'make_workflow("prod_" + tag_name, prod_url, source_ref, branch_name)',
            result,
        )

    def test_preserves_existing_source_refs(self):
        contents = self._make_config_with_source_refs()
        result = sync_repo_with_copybara.ensure_copybara_source_ref_support(
            contents, Path("test.sky")
        )
        self.assertIn("source_refs = {}", result)
        self.assertIn("source_ref = source_refs.get(branch_name, branch_name)", result)
        self.assertIn("def sync_branch(branch_name):", result)

    def test_preserves_legacy_source_refs_with_public_files(self):
        contents = self._make_legacy_config_with_source_refs()
        result = sync_repo_with_copybara.ensure_copybara_source_ref_support(
            contents, Path("test.sky")
        )
        self.assertIn("source_refs = {}", result)
        self.assertIn("source_ref = source_refs.get(branch_name, branch_name)", result)
        self.assertIn('branch_public_files = ["**"]', result)
        self.assertIn("branch_public_files,\n    )", result)

    def test_exits_when_sync_branch_not_found(self):
        contents = textwrap.dedent("""\
            source_url = "https://github.com/10gen/mongo.git"
            test_branch_prefix = "copybara_test_branch"
            source_refs = {}
            """)
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.ensure_copybara_source_ref_support(contents, Path("test.sky"))

    def test_exits_when_test_branch_prefix_not_found(self):
        contents = textwrap.dedent("""\
            source_url = "https://github.com/10gen/mongo.git"

            def sync_branch(branch_name, branch_excluded_files = []):
                pass
            """)
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.ensure_copybara_source_ref_support(contents, Path("test.sky"))


class TestValidatePreviewExclusions(unittest.TestCase):
    """Verify dry-run output validation catches forbidden files."""

    def _make_sync_with_preview(
        self,
        files: list[str],
        branch: str = "master",
        branch_excluded_patterns: list[str] | None = None,
    ) -> sync_repo_with_copybara.PreparedBranchSync:
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        root = Path(tmpdir)

        config_path = root / "copy.bara.sky"
        write_base_copybara_config(config_path, common_includes=["README.md"])
        branch_excluded_patterns = branch_excluded_patterns or []
        if branch_excluded_patterns:
            exclude_entries = "\n".join(f'    "{pattern}",' for pattern in branch_excluded_patterns)
            config_path.write_text(
                config_path.read_text()
                + "\nbranch_files_to_exclude = [\n"
                + f"{exclude_entries}\n"
                + "]\n"
                + f'sync_branch("{branch}", branch_files_to_exclude)\n'
            )
        else:
            config_path.write_text(config_path.read_text() + f'\nsync_branch("{branch}")\n')

        preview_dir = root / "preview" / "checkout"
        preview_dir.mkdir(parents=True)
        for file_path in files:
            full_path = preview_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text("content")

        return sync_repo_with_copybara.PreparedBranchSync(
            branch=branch,
            source_ref="abc123",
            config_sha="sha123",
            workflow_name=f"prod_{branch}",
            config_file=config_path,
            preview_dir=root / "preview",
            docker_command=("echo",),
        )

    def test_passes_when_no_excluded_files_present(self):
        sync = self._make_sync_with_preview(
            [
                "src/mongo/db/catalog/collection.cpp",
                "README.md",
                "jstests/core/basic.js",
            ]
        )
        sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_modules_directory_present(self):
        sync = self._make_sync_with_preview(
            [
                "src/mongo/db/modules/enterprise/something.cpp",
            ]
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError) as ctx:
            sync_repo_with_copybara.validate_preview_exclusions(sync)
        self.assertIn("preview validation", ctx.exception.stage)

    def test_fails_when_agents_md_present(self):
        sync = self._make_sync_with_preview(["AGENTS.md"])
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_private_third_party_present(self):
        sync = self._make_sync_with_preview(
            [
                "src/third_party/private/secret.h",
            ]
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_cursor_directory_present(self):
        sync = self._make_sync_with_preview(
            [
                ".cursor/rules/my_rule.md",
            ]
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_github_codeowners_present(self):
        sync = self._make_sync_with_preview(
            [
                ".github/CODEOWNERS",
            ]
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_monguard_present(self):
        sync = self._make_sync_with_preview(
            [
                "monguard/config.yaml",
            ]
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_branch_specific_excluded_file_present(self):
        sync = self._make_sync_with_preview(
            ["docs/private-notes/secret.md"],
            branch="v8.2",
            branch_excluded_patterns=["docs/private-notes/**"],
        )
        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_private_commercial_header_present(self):
        sync = self._make_sync_with_preview([])
        public_header_path = sync.preview_dir / "checkout" / "src/mongo/util/public_header.h"
        public_header_path.parent.mkdir(parents=True, exist_ok=True)
        public_header_path.write_text(
            textwrap.dedent("""\
            /**
             *    Copyright (C) 2025-present MongoDB, Inc. and subject to applicable commercial license.
             */
            """)
        )

        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_excluded_broken_symlink_present(self):
        if sys.platform == "win32":
            self.skipTest("symlink permissions vary on Windows")

        sync = self._make_sync_with_preview([])
        excluded_symlink = sync.preview_dir / "checkout" / "AGENTS.md"
        os.symlink("missing-target", excluded_symlink)

        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)

    def test_fails_when_excluded_symlinked_directory_present(self):
        if sys.platform == "win32":
            self.skipTest("symlink permissions vary on Windows")

        sync = self._make_sync_with_preview([])
        excluded_symlink_dir = sync.preview_dir / "checkout" / "src/mongo/db/modules"
        excluded_symlink_dir.parent.mkdir(parents=True, exist_ok=True)
        os.symlink("missing-target", excluded_symlink_dir)

        with self.assertRaises(sync_repo_with_copybara.BranchSyncError):
            sync_repo_with_copybara.validate_preview_exclusions(sync)


class TestRedactSecrets(unittest.TestCase):
    """Verify token redaction in log output."""

    def test_redacts_known_tokens(self):
        original_secrets = list(sync_repo_with_copybara.REDACTED_STRINGS)
        try:
            sync_repo_with_copybara.REDACTED_STRINGS.clear()
            sync_repo_with_copybara.REDACTED_STRINGS.append("ghp_SuperSecretToken123")

            result = sync_repo_with_copybara.redact_secrets(
                "Using token ghp_SuperSecretToken123 for auth"
            )
            self.assertNotIn("ghp_SuperSecretToken123", result)
            self.assertIn("<REDACTED>", result)
        finally:
            sync_repo_with_copybara.REDACTED_STRINGS.clear()
            sync_repo_with_copybara.REDACTED_STRINGS.extend(original_secrets)

    def test_redacts_github_url_credentials(self):
        url = "https://x-access-token:ghs_abc123xyz@github.com/10gen/mongo.git"
        result = sync_repo_with_copybara.redact_secrets(url)
        self.assertNotIn("ghs_abc123xyz", result)
        self.assertIn("https://x-access-token:<REDACTED>@github.com", result)

    def test_redacts_unknown_github_url_credentials(self):
        """Credentials not in REDACTED_STRINGS are still caught by the regex fallback."""
        url = "https://x-access-token:unknown_ambient_token@github.com/mongodb/mongo.git"
        result = sync_repo_with_copybara.redact_secrets(url)
        self.assertNotIn("unknown_ambient_token", result)

    def test_preserves_non_sensitive_text(self):
        text = "Running copybara for branch master"
        result = sync_repo_with_copybara.redact_secrets(text)
        self.assertEqual(text, result)

    def test_handles_empty_redacted_strings_list(self):
        original_secrets = list(sync_repo_with_copybara.REDACTED_STRINGS)
        try:
            sync_repo_with_copybara.REDACTED_STRINGS.clear()
            result = sync_repo_with_copybara.redact_secrets("no secrets here")
            self.assertEqual("no secrets here", result)
        finally:
            sync_repo_with_copybara.REDACTED_STRINGS.clear()
            sync_repo_with_copybara.REDACTED_STRINGS.extend(original_secrets)

    def test_read_git_file_returns_unredacted_source_text(self):
        source_text = (
            'url = repo_url.replace("https://github.com", '
            'f"https://x-access-token:{token}@github.com", 1)\n'
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir)
            git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull}
            subprocess.run(
                ["git", "init"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                env=git_env,
            )
            subprocess.run(
                ["git", "config", "--local", "user.email", "test@example.com"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                env=git_env,
            )
            subprocess.run(
                ["git", "config", "--local", "user.name", "Test User"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                env=git_env,
            )
            source_path = repo_dir / "helper.py"
            source_path.write_text(source_text)
            subprocess.run(
                ["git", "add", "helper.py"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                env=git_env,
            )
            subprocess.run(
                ["git", "commit", "-m", "add helper"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                env=git_env,
            )

            stdout = io.StringIO()
            os.chdir(Path(__file__).resolve().parents[2])
            with redirect_stdout(stdout):
                result = sync_repo_with_copybara.read_git_file(repo_dir, "HEAD", "helper.py")

        self.assertEqual(source_text, result)
        self.assertIn("https://x-access-token:<REDACTED>@github.com", stdout.getvalue())
        self.assertNotIn("https://x-access-token:{token}@github.com", stdout.getvalue())


class TestExtractSkyExcludedPatternsRejectsDuplicates(unittest.TestCase):
    """Verify that duplicate common_files_to_exclude definitions are rejected."""

    def test_rejects_multiple_common_files_to_exclude_definitions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            sky_path.write_text(
                textwrap.dedent("""\
                common_files_to_exclude = [
                    "src/mongo/db/modules/**",
                ]

                common_files_to_exclude = [
                    "harmless_file.txt",
                ]
                """)
            )

            with self.assertRaises(SystemExit):
                sync_repo_with_copybara.extract_sky_excluded_patterns(str(sky_path))

    def test_accepts_single_definition(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(sky_path)
            patterns = sync_repo_with_copybara.extract_sky_excluded_patterns(str(sky_path))
            self.assertIsInstance(patterns, set)
            self.assertTrue(len(patterns) > 0)

    def test_ignores_commented_out_definitions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sky_path = Path(tmpdir) / "copy.bara.sky"
            sky_path.write_text(
                textwrap.dedent("""\
                # common_files_to_exclude = ["should_be_ignored/**"]
                common_files_to_exclude = [
                    "src/mongo/db/modules/**",
                ]
                """)
            )

            patterns = sync_repo_with_copybara.extract_sky_excluded_patterns(str(sky_path))
            self.assertNotIn("should_be_ignored/**", patterns)
            self.assertIn("src/mongo/db/modules/**", patterns)


class TestMatchesExcludedPattern(unittest.TestCase):
    """Verify path matching logic for excluded patterns."""

    def test_directory_pattern_matches_files_in_subtree(self):
        self.assertTrue(
            sync_repo_with_copybara.matches_excluded_pattern(
                "src/mongo/db/modules/enterprise/foo.cpp", "src/mongo/db/modules/"
            )
        )

    def test_directory_pattern_matches_directory_itself(self):
        self.assertTrue(
            sync_repo_with_copybara.matches_excluded_pattern(
                "src/mongo/db/modules", "src/mongo/db/modules/"
            )
        )

    def test_directory_pattern_with_glob_suffix(self):
        self.assertTrue(
            sync_repo_with_copybara.matches_excluded_pattern(
                "src/third_party/private/secret.h", "src/third_party/private/**"
            )
        )

    def test_directory_pattern_does_not_match_unrelated_path(self):
        self.assertFalse(
            sync_repo_with_copybara.matches_excluded_pattern(
                "src/mongo/db/storage/wiredtiger.cpp", "src/mongo/db/modules/"
            )
        )

    def test_exact_file_pattern_matches_exact_path(self):
        self.assertTrue(sync_repo_with_copybara.matches_excluded_pattern("AGENTS.md", "AGENTS.md"))

    def test_exact_file_pattern_does_not_match_different_file(self):
        self.assertFalse(sync_repo_with_copybara.matches_excluded_pattern("README.md", "AGENTS.md"))

    def test_exact_file_pattern_does_not_match_subdirectory_file(self):
        self.assertFalse(
            sync_repo_with_copybara.matches_excluded_pattern("docs/AGENTS.md", "AGENTS.md")
        )

    def test_directory_pattern_does_not_match_prefix_overlap(self):
        """monguard/ should not match monguard_extra/."""
        self.assertFalse(
            sync_repo_with_copybara.matches_excluded_pattern("monguard_extra/file.txt", "monguard/")
        )


class TestCanonicalizeExcludedPattern(unittest.TestCase):
    """Verify pattern normalization for preview exclusion matching."""

    def test_trailing_slash_becomes_directory_pattern(self):
        self.assertEqual(
            sync_repo_with_copybara.canonicalize_excluded_pattern("monguard/"),
            "monguard/",
        )

    def test_glob_suffix_becomes_directory_pattern(self):
        self.assertEqual(
            sync_repo_with_copybara.canonicalize_excluded_pattern("monguard/**"),
            "monguard/",
        )

    def test_exact_file_stays_exact(self):
        self.assertEqual(
            sync_repo_with_copybara.canonicalize_excluded_pattern("AGENTS.md"),
            "AGENTS.md",
        )

    def test_rejects_wildcard_patterns(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.canonicalize_excluded_pattern("*.py")

    def test_rejects_empty_pattern(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.canonicalize_excluded_pattern("")

    def test_rejects_slash_only_pattern(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.canonicalize_excluded_pattern("/")


class TestAssembleCopybaraConfig(unittest.TestCase):
    """Verify that base config and fragments are correctly concatenated."""

    def test_combines_base_and_single_fragment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base = root / "base.sky"
            base.write_text('# base config\nsource_url = "foo"\n')

            fragment = root / "master.sky"
            fragment.write_text('sync_branch("master")\n')

            output = root / "assembled.sky"
            sync_repo_with_copybara.assemble_copybara_config(base, [fragment], output)

            assembled = output.read_text()
            self.assertIn("# base config", assembled)
            self.assertIn('sync_branch("master")', assembled)
            self.assertIn(f"# BEGIN {fragment.as_posix()}", assembled)
            self.assertIn(f"# END {fragment.as_posix()}", assembled)

    def test_combines_base_and_multiple_fragments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base = root / "base.sky"
            base.write_text("# base\n")

            frag_a = root / "a.sky"
            frag_a.write_text('sync_branch("a")\n')
            frag_b = root / "b.sky"
            frag_b.write_text('sync_branch("b")\n')

            output = root / "out.sky"
            sync_repo_with_copybara.assemble_copybara_config(base, [frag_a, frag_b], output)

            assembled = output.read_text()
            self.assertIn('sync_branch("a")', assembled)
            self.assertIn('sync_branch("b")', assembled)
            idx_a = assembled.index('sync_branch("a")')
            idx_b = assembled.index('sync_branch("b")')
            self.assertLess(idx_a, idx_b)

    def test_output_ends_with_newline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            base = root / "base.sky"
            base.write_text("# base\n")
            fragment = root / "f.sky"
            fragment.write_text('sync_branch("x")\n')
            output = root / "out.sky"
            sync_repo_with_copybara.assemble_copybara_config(base, [fragment], output)
            self.assertTrue(output.read_text().endswith("\n"))


class TestParseBranchList(unittest.TestCase):
    """Verify edge-case handling for comma-separated branch parsing."""

    def test_returns_empty_for_none(self):
        self.assertEqual(sync_repo_with_copybara.parse_branch_list(None), [])

    def test_returns_empty_for_blank_string(self):
        self.assertEqual(sync_repo_with_copybara.parse_branch_list(""), [])

    def test_single_branch(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_branch_list("master"),
            ["master"],
        )

    def test_deduplicates_preserving_order(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_branch_list("v8.2, master, v8.2"),
            ["v8.2", "master"],
        )

    def test_strips_whitespace(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_branch_list("  master , v8.0 , v8.2 "),
            ["master", "v8.0", "v8.2"],
        )

    def test_skips_empty_entries_from_trailing_comma(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_branch_list("master,v8.0,"),
            ["master", "v8.0"],
        )

    def test_skips_empty_entries_from_double_comma(self):
        self.assertEqual(
            sync_repo_with_copybara.parse_branch_list("master,,v8.0"),
            ["master", "v8.0"],
        )


class TestRealCopybaraSkyConfiguration(unittest.TestCase):
    """Integration tests for the checked-in Copybara config files."""

    REAL_COPYBARA_ROOT = Path(__file__).resolve().parents[2]
    REAL_SKY_PATH = REAL_COPYBARA_ROOT / sync_repo_with_copybara.COPYBARA_BASE_CONFIG_PATH
    REAL_TEMPLATE_PATH = (
        REAL_COPYBARA_ROOT / "buildscripts" / "copybara" / "copybara_path_rules.bara.sky.template"
    )
    REAL_PATH_RULES_PATH = REAL_COPYBARA_ROOT / sync_repo_with_copybara.COPYBARA_PATH_RULES_PATH
    REAL_PATH_RULES_MODULE_PATH = (
        REAL_COPYBARA_ROOT / sync_repo_with_copybara.COPYBARA_PATH_RULES_MODULE_PATH
    )
    REAL_GENERATED_EVERGREEN_PATH = (
        REAL_COPYBARA_ROOT / generate_evergreen.COPYBARA_EVERGREEN_GENERATED_CONFIG_PATH
    )

    @unittest.skipUnless(
        REAL_PATH_RULES_MODULE_PATH.is_file()
        and REAL_TEMPLATE_PATH.is_file()
        and REAL_PATH_RULES_PATH.is_file(),
        "checked-in Copybara source-of-truth files not found at expected paths",
    )
    def test_real_path_rules_module_matches_rendered_source_of_truth(self):
        rendered = render_copybara_path_rules_module_from_files(
            self.REAL_TEMPLATE_PATH,
            self.REAL_PATH_RULES_PATH,
        )
        self.assertEqual(self.REAL_PATH_RULES_MODULE_PATH.read_text(), rendered)

    @unittest.skipUnless(
        REAL_SKY_PATH.is_file(),
        "checked-in copy.bara.sky not found at expected path",
    )
    def test_real_base_config_loads_generated_path_rules_module(self):
        contents = self.REAL_SKY_PATH.read_text()
        self.assertIn('load("copybara_path_rules"', contents)
        self.assertIn('"common_files_to_include"', contents)
        self.assertIn('"common_files_to_exclude"', contents)

    @unittest.skipUnless(
        REAL_PATH_RULES_PATH.is_file(),
        "checked-in Copybara path rules JSON not found at expected path",
    )
    def test_real_path_rules_json_lists_are_sorted(self):
        payload = json.loads(self.REAL_PATH_RULES_PATH.read_text())

        for field_name in ("common_files_to_include", "common_files_to_exclude"):
            with self.subTest(field_name=field_name):
                self.assertEqual(
                    payload[field_name],
                    sorted(payload[field_name]),
                    f"{field_name} in copybara_path_rules.json must remain sorted.",
                )

    @unittest.skipUnless(
        REAL_SKY_PATH.is_file(),
        "checked-in copy.bara.sky not found at expected path",
    )
    def test_real_fragments_match_expected_mainline_branch_allowlist(self):
        branch_to_fragment = sync_repo_with_copybara.discover_copybara_branches(
            str(self.REAL_COPYBARA_ROOT)
        )
        mainline_branches = sorted(
            branch for branch in branch_to_fragment if not branch.endswith("-hotfix")
        )
        hotfix_branches = sorted(
            branch for branch in branch_to_fragment if branch.endswith("-hotfix")
        )

        self.assertEqual(mainline_branches, ["master", "v7.0", "v8.0", "v8.2"])
        self.assertTrue(all(branch.endswith("-hotfix") for branch in hotfix_branches))

    @unittest.skipUnless(
        REAL_GENERATED_EVERGREEN_PATH.is_file(),
        "checked-in generated Copybara Evergreen config not found at expected path",
    )
    def test_real_generated_evergreen_matches_copybara_fragments(self):
        self.assertEqual(
            self.REAL_GENERATED_EVERGREEN_PATH.read_text(),
            generate_evergreen.render_expected_copybara_evergreen(self.REAL_COPYBARA_ROOT),
        )


class TestEvergreenProjectGuard(unittest.TestCase):
    def test_passes_for_expected_master_project(self):
        sync_repo_with_copybara.ensure_expected_evergreen_project(
            {"project": sync_repo_with_copybara.EXPECTED_EVERGREEN_PROJECT}
        )

    def test_fails_for_missing_project(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.ensure_expected_evergreen_project({})

    def test_fails_for_non_master_project(self):
        with self.assertRaises(SystemExit):
            sync_repo_with_copybara.ensure_expected_evergreen_project(
                {"project": "mongodb-mongo-master-nightly"}
            )


class TestHotfixTaskActivation(unittest.TestCase):
    def test_get_hotfix_branches_for_release(self):
        hotfix_branches = sync_repo_with_copybara.get_hotfix_branches_for_release(
            "v8.2",
            ["master", "v8.2", "v8.2-hotfix", "v8.2.6-hotfix", "v8.0.10-hotfix"],
        )

        self.assertEqual(hotfix_branches, ["v8.2-hotfix", "v8.2.6-hotfix"])

    @patch("buildscripts.copybara.sync_repo_with_copybara.retry_operation")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_evergreen_api")
    @patch("buildscripts.copybara.sync_repo_with_copybara.check_destination_branch_exists")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    def test_activate_new_hotfix_tasks_activates_unsynced_hotfix_task(
        self,
        mock_branch_exists_remote,
        mock_check_destination_branch_exists,
        mock_get_api,
        mock_retry_operation,
    ):
        mock_branch_exists_remote.return_value = True
        mock_check_destination_branch_exists.return_value = False

        inactive_task = MagicMock()
        inactive_task.display_name = "sync_copybara_v8_2_6_hotfix"
        inactive_task.activated = False
        inactive_task.task_id = "task_1"

        mock_api = mock_get_api.return_value
        mock_api.tasks_by_build.return_value = [inactive_task]

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                config_file,
                prod_url=sync_repo_with_copybara.TEST_REPO_URL,
            )

            sync_repo_with_copybara.activate_new_hotfix_tasks(
                selected_branches=["v8.2"],
                configured_branches=["master", "v8.2", "v8.2.6-hotfix"],
                expansions={"build_id": "build_1"},
                tokens_map={
                    sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
                    sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
                    sync_repo_with_copybara.TEST_REPO_URL: "test-token",
                },
                config_file=config_file,
            )

        mock_retry_operation.assert_called_once_with(
            mock_api.configure_task,
            "task_1",
            activated=True,
            tries=3,
            delay_seconds=5,
            backoff_factor=2,
        )
        self.assertEqual(
            mock_check_destination_branch_exists.call_args.args[0].destination.repo_name,
            sync_repo_with_copybara.TEST_REPO_NAME,
        )

    @patch("buildscripts.copybara.sync_repo_with_copybara.retry_operation")
    @patch("buildscripts.copybara.sync_repo_with_copybara.get_evergreen_api")
    @patch("buildscripts.copybara.sync_repo_with_copybara.check_destination_branch_exists")
    @patch("buildscripts.copybara.sync_repo_with_copybara.branch_exists_remote")
    def test_activate_new_hotfix_tasks_skips_existing_public_branch(
        self,
        mock_branch_exists_remote,
        mock_check_destination_branch_exists,
        mock_get_api,
        mock_retry_operation,
    ):
        mock_branch_exists_remote.return_value = True
        mock_check_destination_branch_exists.return_value = True
        mock_get_api.return_value.tasks_by_build.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "copy.bara.sky"
            write_base_copybara_config(
                config_file,
                prod_url=sync_repo_with_copybara.TEST_REPO_URL,
            )

            sync_repo_with_copybara.activate_new_hotfix_tasks(
                selected_branches=["v8.2"],
                configured_branches=["master", "v8.2", "v8.2.6-hotfix"],
                expansions={"build_id": "build_1"},
                tokens_map={
                    sync_repo_with_copybara.SOURCE_REPO_URL: "source-token",
                    sync_repo_with_copybara.PUBLIC_GITHUB_APP_REPO_URL: "prod-token",
                    sync_repo_with_copybara.TEST_REPO_URL: "test-token",
                },
                config_file=config_file,
            )

        mock_retry_operation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
