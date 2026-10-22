# Connected engines acceptance — 2026-10-22

- Full suite: **281 tests passed**, 468.741 seconds. After the full run, the HTTP response-close fix and OSV --all-packages command were rechecked with 3 HTTP integration tests and 5 scanner execution tests. The 3 CI gate tests also passed separately.
- Expanded `check_submission.py`: **22 tests passed**; installed OSV hash/readiness verified. Frontend TypeScript/build passed. This remains bounded acceptance, not certification of every external connector.
- Official OSV-Scanner 2.7.0 Windows binary installed and SHA-256 checked. Actual source job in isolated QA produced 5 findings. CI gate returned 1 for the vulnerable public fixture and 0 for the clean public fixture, both with package coverage.
- Own HTTP baseline executes one GET against configured loopback HTML only. Actual browser action created 3 persisted observations; secured response and redirect/permission/config-change cases were tested. Full external active DAST is not claimed.
- Primary API restarted with all rows preserved; backup `primary-before-functional-20261022-015505.db`. OSV is available to subsequent source jobs. No automatic external target was configured.
- `Start-TRACE-Demo.cmd` / `run_demo.py`: a separate local app on 5174 plus the HTTP fixture on 8878, in one process. Browser execution succeeded. A real source job on generated fixtures produced **6 findings** (OSV + Python AST), scan `scan-0000000-063deddd4a71`. Main database is separate. Sources are never executed.
- External GitLab runner needs a real repository/provider; Semgrep remains blocked by Windows certificate-store access. WSL enumeration also returned access denied. No protections were disabled.

## Previous submission acceptance — 2026-10-22

- Full updated backend suite: **276 tests passed**, 450.781 seconds. Frontend TypeScript and production build passed; API client 7/7; semantic and live VEX smoke passed.
- `tools/check_submission.py`: **14 isolated journey tests passed**, release files and existing SQLite database validated. Status `CORE_ACCEPTANCE_PASSED` refers to the documented prototype scope, not complete external integrations.
- Added ZAP Traditional JSON import with bounded validation, URL query/fragment removal, dedicated web evidence, unknown reachability, analyst review and VEX without invented CVSS. Imported SCA/SAST/DAST reports now retain the direction in scanner results.
- Actual browser on an isolated QA database: file chooser and upload -> DAST report -> ZAP-10020 detail -> review -> reload -> API process restart -> persisted finding/review. This was an explicitly labelled **test fixture**, not a live ZAP scan. QA scan: `scan-0000000-8c5fd4f937e8`.
- Primary release restarted on port 5173 with backup `primary-before-functional-20261022-013042.db`; all preexisting table rows compared and preserved. Primary demo findings were not replaced by QA fixtures.
- Submission guide and limitations: [SUBMISSION.md](SUBMISSION.md). Capability matrix updated. Active DAST, external CI providers, missing SCA binaries and the Semgrep certificate-store restriction remain external requirements.

## Previous acceptance — 2026-10-21

The primary release runs at http://127.0.0.1:5173 with the existing database. Restart compared all stored rows with a SQLite backup; no existing records changed.

## Verified
- Full backend suite: 271 tests passed (445.378 seconds). Additional native scanner and execution-contract tests passed after the final usage-index optimization.
- Frontend TypeScript, production build and smoke checks passed. API client tests: 7 passed.
- Browser, isolated QA database: local Python source -> durable background job -> persisted scan -> real TRACE-PY-001 observation at app.py:3 -> review mark -> reload retaining the mark. Job e9fa61f0c5cf4748a93870bff2dda87d; scan scan-0000000-8963dc020792.
- Scanner failures and malformed reports no longer count as successful scans. Missing engines and incomplete coverage remain visible.
- Native AST findings retain their evidence on reassessment, remain under investigation in VEX, use CSAF rule identifiers rather than invalid CVE values, and have no invented CVSS score.
- SQLite timestamps are serialized as UTC.

## Native Python analysis scope
TRACE Python AST inspects syntax without executing source. Four bounded rules cover eval/exec, unsafe deserialization, yaml.load loaders and subprocess shell=True. It is Python-only, has file/time/size limits, does not perform taint/dataflow analysis and does not establish exploitability. Findings require analyst review. It is independent of Semgrep and is labelled accordingly.

## External blockers / not demonstrated
- Semgrep 1.181.0 and isolated compatibility 1.145.0 both fail in the native engine because Windows denies access to its certificate store (error 5). The compatibility CLI starts after dependency pinning, but real scanning still fails. Neither is marked ready. TLS verification was not disabled.
- DAST has no explicit authorized target URL; the user's acknowledgement did not supply one. No arbitrary external site was scanned.
- Other absent external scanner engines remain unavailable; a partial scan does not establish safety. External CI provider integration and full external DAST/SCA operation are not certified by this local acceptance.

Evidence and test logs are in the workspace work/ directory; UI screenshot is outputs/TRACE-native-functional-proof.png. The test database is separate from the user's primary database.
