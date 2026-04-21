// Helper for finding the local python binary.

export function getPython3Binary() {
    // Use RESMOKE_PYTHON if set, pointing to the python that should be used.
    const resmokePython = _getEnv("RESMOKE_PYTHON");
    if (resmokePython) {
        jsTest.log.info("Using Python from RESMOKE_PYTHON: " + resmokePython);
        return resmokePython;
    }

    // On windows it is important to use python vs python3
    // or else we will pick up a python that is not in our venv
    clearRawMongoProgramOutput();
    assert.eq(runNonMongoProgram("python", "--version"), 0);
    const pythonVersion = rawMongoProgramOutput("Python"); // Will look like "Python 3.13.4\n"
    const match = pythonVersion.match(/Python 3\.(\d+)\./);
    if (match && match[1] >= 13) {
        jsTest.log.info(
            "Found python 3." + match[1] + " by default. Likely this is because we are using a virtual environment.",
        );
        return "python";
    }

    const paths = [
        "/opt/venv/bin/python3",
        "/opt/mongodbtoolchain/v5/bin/python3.13",
        "/opt/mongodbtoolchain/v4/bin/python3",
        "/usr/bin/python3",
        "/cygdrive/c/python/python313/python.exe",
        "c:/python/python313/python.exe",
    ];
    for (let p of paths) {
        if (fileExists(p)) {
            jsTest.log.info("Found python3 in default location " + p);
            return p;
        }
    }

    assert(/Python 3/.exec(pythonVersion));

    // We are probs running on mac
    jsTest.log.info("Did not find python3 in a virtualenv or default location");
    return "python3";
}
