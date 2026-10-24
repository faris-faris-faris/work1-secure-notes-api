# Submission status — repository published

Everything in this folder is complete, verified and published. This file records
the state so that nothing needs to be repeated before the email is sent.

The reports carry the student's name (Wu ZiYang) and HDU number (23320121); no
variant was assigned, so the variant field is "—".

| Item | Value |
|---|---|
| Public repository | <https://github.com/faris-faris-faris/work1-secure-notes-api> |
| Last successful pipeline run | <https://github.com/faris-faris-faris/work1-secure-notes-api/actions/runs/40105508780> |
| Commit of that run | `7748614` |
| Jobs | `test` (Node 22), `test` (Node 24), `lint`, `sast`, `sca` — all **success** |
| Raw run record | [`docs/evidence/github-actions-run.txt`](evidence/github-actions-run.txt) |

## What was published

```bash
git init
git add .
git commit -m "feat: secure notes API, CI with SAST/SCA, CVE-2022-22965 study"
git commit -m "fix: upgrade express and zod, pin body-parser 2.4.0 for a clean SCA gate"
git remote add origin https://github.com/faris-faris-faris/work1-secure-notes-api.git
git push -u origin main
```

The first CI run failed the `sca` job on two high advisories. They were fixed
in the `fix:` commit:

* `express` 5.1 → 5.3.0
* `zod` 3.25 → 4.6.7
* `overrides: { "body-parser": "2.4.0" }`

`npm audit` now reports 0 vulnerabilities and the 52 tests pass. Every run after
that fix has been green on every job; the one linked above (`40105508780`) is
the run for the current `main` (`7748614`).

## CI evidence

`docs/screenshots/ci-local.png` is a real run of the exact commands in
`.github/workflows/ci.yml` on this machine (`scripts/ci-local.ps1`); it is
labelled as a local run in the README and in both reports.

The GitHub run is evidenced by its public run URL and by
`docs/evidence/github-actions-run.txt`, which contains the API response captured
after the run: workflow conclusions and the per-job conclusion for
`40105508780`.

## Rebuilding the PDFs

If any Markdown changes, regenerate the reports:

```bash
python docs/build_report.py --pdf docs/report_en.md docs/report_zh.md
```
