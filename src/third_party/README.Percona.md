# Vendoring a Third-Party Library and Updating SBOM

The document describes the process of vendoring a third-party library in
Percona Server for MongoDB (hereinafter, PSMDB) using `libarchive` as an
example. The document follows the major steps of the upstream [policy][10] but
adds some details we consider important. It makes sense to read the upstream
policy before proceeding with this document.

[10]: https://github.com/percona/percona-server-mongodb/blob/master/src/third_party/README.md

## Adding a New Library
### 1. Fork the repository
We don’t copy the library’s code into the PSMDB repository straight from the
library’s repository. Instead, please raise an IT ticket to fork the library’s
repository in the [Percona-Lab](https://github.com/Percona-Lab) organization on
GitHub. Ideally, all branches, and especially tags, should be cloned as well.
If the original library repository is too large to clone, clone at least the
named tag and/or branch corresponding to the version you plan to include in
PSMDB. Please avoid referencing the code you plan to include in PSMDB only by
a commit hash, as the hash would be impossible to use in the SBOM file
(please see below). In the IT ticket mentioned above, don’t forget to request
that the PSMDB repository permissions be mirrored to the newly created clone.

Example:
We clone the upstream https://github.com/libarchive/libarchive into
https://github.com/Percona-Lab/libarchive, including all branches and tags,
giving PSMD developers the same access to the clone as they have to the PSMDB
repository itself.

After the fork has been created, a PSMDB developer needs to create a branch
there. If there is a tag for the version we plan to include in PSMDB, then
the branch should be named `<tag>-percona`. For instance, to incorporate
`libarchive` version `3.8.4`, we see the tags and find `v3.8.4`, from which
we create the `v3.8.4-percona` branch as follows:
```shell
$ git clone git@github.com:Percona-Lab/libarchive.git
$ pushd libarchive
$ git tags
...
v3.8.4
...
$ git switch -c v3.8.4-percona v3.8.4
$ git push origin v3.8.4-percona
```
The purpose of the branch is to provide a well-defined “place” to store our
fixes/improvements for the mentioned library version, should we need them.
That way, we can start using a fixed library version even before the fix
itself has been submitted and accepted into the upstream library repo.
Please don’t include any patches that are relevant to Percona exclusively
in the branch or in the cloned repo in general. Otherwise, we risk ending
up with a complete mess when syncing the clone with upstream. We’ll show
below where to place Percona-specific patches.

### 2. Create the directory in the PSMDB worktree
As a rule, a third-party dependency called `<name>` is stored in the
`src/third_party/<name>` directory of the PSMDB repository; the directory
name should _not_ include version, commit hash, etc. as a suffix. Such
information goes to the `README.third_party.md` file, which we will consider
later. Under the `<name>` directory, the files are also organized in separate
subdirectories. Their structure can depend on a particular third-party library,
but typically, we have:
- `src/third_party/<name>/dist/`: here we keep the source code of a third-party
  library
- `src/third_party/<name>/scripts/`: storgate for the scripts working with
  library source code, including but not limited to the mandatory `import.sh`
  script (see below) that copies the source code of the library from the
  `Percona-Lab/<name>` repository to the `src/third_party/<name>/dist/`
  directory and removes any unnecessary files. We will cover the script in
  more detail below.
- `src/third_party/<name>/patches/`: (optional) a directory for Percona-specific
  patches to the third-party library in question
- `src/third_party/<name>/platform/build_<os_type>_<cpu_architecture>`:
  a directory for OS- and/or architecture-specific files, like `config.h`
- `src/third_party/<name>/BUILD.bazel`: a top-level `bazel` file for building
  the library as a part for PSMDB repo
- `src/third_party/<name>/README.md`: (optional) library-specific notes

For instance, `libarchive` is structured as follows:
```
src/third_party/libarchive/dist/README.md
src/third_party/libarchive/dist/COPYING
src/third_party/libarchive/dist/SECURITY.md

src/third_party/libarchive/dist/libarchive/*.h
src/third_party/libarchive/dist/libarchive/*.c

src/third_party/libarchive/scripts/import.sh

src/third_party/libarchive/platform/build_linux_aarch64/config.h
src/third_party/libarchive/platform/build_linux_x86_64/config.h

src/third_party/libarchive/BUILD.bazel
src/third_party/libarchive/README.md
```

### 3. Create the `import.sh` script
The script clones the branch we created at the stage 1 (`v3.8.4-percona` in
case of `libarchve`) from the cloned repository in `Percona-Lab` organization
(`Percona-Lab/libarchive` in our example) to the `dist` directory and removes
all unnecessary files, keeping only a bare minimum: source code of the library
and files like `LICENSE`, `COPYING`, `CODEOWNERS`, `COPYRIGHT`, `SECURITY.md`,
etc. Pease see `src/third_parth/snappy/scripts/import.sh` and
`src/third_party/libarchive/scripts/import.sh` for the examples.

There are two additional requirements for the script that stem from how the
`buildscripts/sbom_linter.py` script operates. It compares the content of
`sbom.json` with what is imported by `imports.sh`. As a result, the latter
must have the fixed path `src/third_party/<name>/scripts/import.sh` and
assign the library’s version to the `VERSION` variable. For instance, in
`src/third_party/libarchive/scripts/import.sh` we have:
```shell
VERSION="v3.8.4"
```
Next, add execution permissions to the script and run it from the PSMDB
worktree root:
```shell
$ chmod +x src/third_party/libarchive/scripts/import.sh
$ ./src/third_party/libarchive/scripts/import.sh
```
Commit `import.sh` and the `dist` directory to the PSMDB Git repository
(ideally, as a separate commits).

### 4. (Optional) Preparing platform-specific files
After importing the source code, some libraries (e.g., `snappy`, `libarchive`)
require (potentially platform-dependent) configuration before they can be
compiled. Sometimes, the configuration file is easy to obtain, and the
respective commands can be codified in a script. For instance, see
`src/third_party/snappy/scripts/generate_config_headers.sh`. In case of
`libarchive`, however, things are slightly more complicated. Please see
`src/third_party/libarchive/README.md` for details. Anyway, under no
circumstances should the created configuration files be pushed to Percona’s
library fork repository (`Percona-Lab/libarchive` in our example) because
they are not relevant for the `libarchive` as a whole. Those file should be
committed to the PSMDB repository instead.

### 5. Created the BUILD.bazel file, compile and test.
Nothing specific here, just a regular development cycle. Don’t forget to commit
`BUILD.bazel`, though.

### 6. (Optional) Preparing patches
Compilation or testing at stage 5 may reveal some issues that need fixing.
If the fix contains no Percona-specific changes (e.g., a bug fix in
`libarchive` itself or a backport of some changes from a newer version),
push it to the branch created at stage 1. In our example, it is
`v3.8.4-percona`. Conversely, if the fix is highly tailored to Percona’s
use-case and not applicable to other `libarchive` users, create the `patches`
directory and place the fix there as a `.patch` file. Please start the
filename with a number so that patches can be applied later in the correct
order. One can create a patch as follows:
```shell
$ git diff > src/third_party/libarchive/patches/0001_<short_description>.patch
```
Please __never ever commit changes to a third-party library as a regular
commits in the PSMDB repository__, as it mixes third-party code with PSMDB
code in the repo and makes it hard to find changes to the third-party library
in the joint commit history. Instead, commit the created patch files and
amend the `import.sh` script with the following line:
```
git apply patches/*.patch
```
That will apply patches in their numeric order. Please see
`src/third_party/abseil-cpp/scripts/import.sh` as an example.

### 7. Update `sbom.json`
_Manually_ include information about the third-party library in question in
the `sbom.json` file. Please see [here][20] for the list of the fields to
include and their meaning. Below is a (partially collapsed for brevity) example
of what we added to `sbom.json` for the `libarchive` library in `v8.0` branch:
```
{
  <other_things>,
  "components": [
    <other_components>,
    {
      "supplier": {"name": "Organization: github"},
      "name": "libarchive",
      "version": "3.8.4",
      "licenses": [
        {
          "license": {
            "name": "A mix of BSD-2-Clasue and others",
            "url": "https://github.com/libarchive/libarchive/blob/v3.4.0/COPYING"
          }
        }
      ],
      "purl": "pkg:github/libarchive/libarchive@v3.8.4",
      "properties": [
        {"name": "internal:team_responsible", "value": "Percona Server for MongoDB Team"},
        {"name": "emits_persisted_data", "value": "true"},
        {"name": "info_link", "value": "https://www.libarchive.org"},
        {"name": "import_script_path", "value": "src/third_party/libarchive/scripts/import.sh"}
      ],
      "type": "library",
      "bom-ref": "pkg:github/libarchive/libarchive@v3.8.4",
      "evidence": {"occurrences": [{"location": "src/third_party/libarchive"}]},
      "scope": "required"
    }
  ],
  <more_things>
}
```
Please don’t forget to put the third-party library on the dependency list of
MongoDB and specify the dependencies of the library itself. For instance, for
`libarchive` in branch `v8.0` we have:
```
{
  <other_things>,
  "dependencies": [
    {
      "ref": "pkg:github/mongodb/mongo@v8.0",
      "dependsOn": [
        .....<tons_of_other_libs>...,
        "pkg:github/libarchive/libarchive@v3.8.4"
      ]
    },
    <other_dependencies>,
    {
      "ref": "pkg:github/libarchive/libarchive@v3.8.4",
      "dependsOn": []
    }
  ]
}
```
Note. In the `master` branch, the format of `bom-ref` has changed. Instead
of being equal to `purl` field, it is just a UUID generated by the `uuidgen`
utility.

After amending `sbom.json` , validate it with the script:
```shell
$ source <path_to_venv>/bin/activate
(venv) $ python buildscripts/sbom_linter.py
```
where `<path_to_venv>` is a path to the Python virtual environment that was
previously set up for this particular branch/commit of PSMDB, including
installing all the dependencies with either `pip` or `poetry`.

Additionally, one can use `cyclondx` tool to validate `sbom.json`. The tool can
be downloaded [here](https://github.com/CycloneDX/cyclonedx-cli/releases) and
run as below:
```shell
$ ./cyclonedx-linux-x64 validate --input-file <path_to_sbom_json>
```
Commit updated `sbom.json`.

[20]: https://github.com/percona/percona-server-mongodb/blob/master/src/third_party/README.md#sbom


### 8. Regenerate `README.third_parthy.md`
This stage is quite simple and straightforward:
```shell
$ source <path_to_venv>/bin/activate
(venv) $ pushd src/third_party/scripts/
(venv) $ python gen_thirdpartyreadme.py
2026-01-25 09:13:30,662 - INFO - ../../../sbom.json JSON data loaded.
2026-01-25 09:13:30,666 - INFO - Markdown file created successfully.
(venv) $ popd
(venv) $ git add README.third_parthy.md
(venv) $ git commit -m "Update README.third_parthy.md"
```
The updated `README.third_parthy.md` will contain version, license, and a
reference to the added third-party library.

## Updating an existing third-party dependency
The process of upgrading an existing third-party library resembles that of
adding a new one with some modifications:
01. Synchronize the Percona’s fork repository with the upstream, e.g., sync
    https://github.com/Percona-Lab/libarchive with
    https://github.com/libarchive/libarchive pulling all new branches and
    tags to the fork.
02. Create a branch in the fork for the desired version, e.g., create branch
    `v4.0.0-percona` in `Percona-Lab/libarchive`
03. Change the `VERSION` value in the `import.sh` to the new version,
    e.g., to `v4.0.0`
04. Run `import.sh`
05. Apply the steps from 4 to 8 above as required
