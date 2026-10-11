const assert = require("assert");
const fs = require("fs");
const path = require("path");

const lock = JSON.parse(fs.readFileSync(path.join(__dirname, "../../package-lock.json"), "utf8"));

// CVE-2026-33228 / GHSA-rf6f-7fwh-wjgh: parse() permits prototype pollution before 3.4.2.
// Check every copy, including nested dependencies and both npm lockfile v2 representations.
const checkVersion = (version, location) => {
    const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
    assert(match, `Unrecognized flatted version at ${location}: ${version}`);
    const [major, minor, patch] = match.slice(1).map(Number);
    assert(
        major > 3 || major === 3 && (minor > 4 || minor === 4 && patch >= 2),
        `CVE-2026-33228: vulnerable flatted@${version} at ${location}; use >=3.4.2`,
    );
};

for (const [location, dependency] of Object.entries(lock.packages || {})) {
    if (location.endsWith("node_modules/flatted") || dependency.name === "flatted") {
        checkVersion(dependency.version, location);
    }
}

const checkDependencies = (dependencies, parent) => {
    for (const [name, dependency] of Object.entries(dependencies || {})) {
        const location = `${parent}/${name}`;
        if (name === "flatted" || dependency.name === "flatted") {
            checkVersion(dependency.version, location);
        }
        checkDependencies(dependency.dependencies, location);
    }
};
checkDependencies(lock.dependencies, "dependencies");
