// Helper for finding the local python binary.

export function getPython3Binary() {
    // On windows it is important to use python vs python3
    // or else we will pick up a python that is not in our venv
    clearRawMongoProgramOutput();
    assert.eq(runNonMongoProgram("python", "--version"), 0);
    const pythonVersion = rawMongoProgramOutput();  // Will look like "Python 3.10.4\n"
    const match = pythonVersion.match(/Python 3\.(\d+)\./);
    if (match && match[1] >= 10) {
        print("Found python 3." + match[1] +
              " by default. Likely this is because we are using a virtual enviorment.");
        return "python";
    }

    const paths = [
        "/opt/venv/bin/python3",
        "/opt/mongodbtoolchain/v4/bin/python3",
        "/usr/bin/python3",
        "/cygdrive/c/python/python310/python.exe",
        "c:/python/python310/python.exe"
    ];
    for (let p of paths) {
        if (fileExists(p)) {
            print("Found python3 in default location " + p);
            return p;
        }
    }

    assert(/Python 3/.exec(pythonVersion));

    // We are probs running on mac
    print("Did not find python3 in a virtualenv or default location");
    return "python3";
}
