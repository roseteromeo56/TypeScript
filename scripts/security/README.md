# Dependency security review

Reviewed on 2026-10-11 against repository base 4fb8c62754ff3a76ba97332413680c8a26ea33ee.
Source: Datadog open library-vulnerability findings for github.com/roseteromeo56/typescript, ordered by severity, then base CVSS score. Multiple versions of one package are separate findings.

| Rank | Package | Severity | Base CVSS | Finding |
| --- | --- | --- | --- | --- |
| 1 | flatted@3.3.1 | critical | 9.3 | [CVE-2026-33228](https://app.datadoghq.eu/security/finding/YzNlMzRlMzljYjRiMWY2ZTc1ZWZlNWI3ZDA5MDBlNzh-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 2 | fast-xml-parser@4.4.1 | high | 9.3 | [CVE-2026-25896](https://app.datadoghq.eu/security/finding/OTg2MmE2MDZmYjZlYTFlNTljMTg5MzljNDJhOTY0M2V-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 3 | minimatch@5.1.6 | high | 8.7 | [CVE-2026-26996](https://app.datadoghq.eu/security/finding/MDZlMmEwYjc2MmUzODZlZjAzNmNmMGMzMWIzNGQ5ZTZ-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 4 | minimatch@3.1.2 | high | 8.7 | [CVE-2026-26996](https://app.datadoghq.eu/security/finding/MTk4ZGU4ZTQwMWVlOGFlZGM2ZWM3ZWU0NTE1MmEzYTB-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 5 | minimatch@9.0.3 | high | 8.7 | [CVE-2026-26996](https://app.datadoghq.eu/security/finding/ZGMwYmFjNzg4NzQzZWY0MTgzODg3YTEyNjJhOGJmMmV-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 6 | underscore@1.13.6 | high | 8.2 | [CVE-2026-27601](https://app.datadoghq.eu/security/finding/MWE4M2FjY2MwMTM0NDMxZmE4ZmY1MTY1OTc3ZjNlZWR-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 7 | serialize-javascript@6.0.2 | high | 8.1 | [CVE-2020-7660](https://app.datadoghq.eu/security/finding/NjEzMTU1NzljNGFmNmVhYjAwODUwZGUxMDYzZGJkN2J-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 8 | lodash@4.17.21 | high | 8.1 | [CVE-2021-23337](https://app.datadoghq.eu/security/finding/OTk3ZmRiMmRhNTM3ZTJjY2M2YWVmNGE5NWNjOGNhZTl-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 9 | js-yaml@4.1.0 | high | 7.5 | [GHSA-5p4m-2wfm-xmqj](https://app.datadoghq.eu/security/finding/OGViZDg2ZjI2YzI1NzQ1NGVjYWQzZDY0MTZjOTFhM2R-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |
| 10 | glob@10.3.10 | high | 7.5 | [CVE-2025-64756](https://app.datadoghq.eu/security/finding/YjZlYmNjMGJhYTkyNzhmMDcwMGY3NTViMWNlMzZiODV-ZDU4ZDU5MzE0NjZmODcwZDQ4MzgxNmQzMDQzM2M5Njk=) |

## Remediation

The highest-severity finding is CVE-2026-33228: prototype pollution in flatted's parse() before 3.4.2. The dependency is used by ESLint through flat-cache; Datadog reports an available exploit but has not established runtime reachability. An npm override and both lockfile representations now select flatted 3.4.4, which Datadog lists as having no known vulnerabilities. This keeps the existing ESLint major version.

Run `npm run test:security` for the regression guard. It checks all flatted copies in both lockfile representations, including nested dependencies, and rejects versions below 3.4.2 and prereleases. It also runs before the compiler suite through `npm test`.

## Verification

- The regression guard failed on the original 3.3.1 lockfile and passed after the update.
- Mutation checks rejected vulnerable root, newly nested, legacy, and legacy-nested copies, plus a prerelease version.
- An offline lockfile scan against the above 10 Datadog findings and their reported fixed-version floors found the critical flatted finding before the change and no occurrence after it. The other nine high-severity findings remain. This was a targeted advisory check, not a complete fresh security scan.
- GitHub Dependabot and code-scanning alert reads returned HTTP 403.
- `npm audit --offline --package-lock-only --json` returned an empty report even for the original vulnerable lockfile; it supplied no usable advisory data and is not evidence of a clean scan.
- `npm ci --offline --ignore-scripts --audit=false` failed with ENOTCACHED because dependencies are not cached. The compiler suite and installed-package exploit behavior could not be tested.
- The registry's integrity hash for 3.4.4 is unavailable offline. The old 3.3.1 hash was removed rather than incorrectly reused. Registry-backed lockfile regeneration should restore the new hash, followed by installation, the full test suite, and an online security scan.
