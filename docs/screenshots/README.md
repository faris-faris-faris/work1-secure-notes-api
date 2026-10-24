# Screenshots — what each image is and where it came from

Every PNG here is produced from the *captured stdout of a real command run*
(`docs/evidence/*.txt`) by `scripts/render_png.py`. The script only adds
terminal styling (background, font, window chrome); the text is the tool's own
output, unmodified except for stripping ANSI colour codes.

| Image | Source transcript | Command that produced the transcript |
|---|---|---|
| `api-demo.png` | `docs/evidence/api-demo.txt` | `scripts/run-demo.ps1` → `node scripts/demo.mjs` |
| `tests.png` | `docs/evidence/tests.txt` | `node --test --test-reporter=spec` |
| `sast-eslint.png` | `docs/evidence/sast.txt` | `eslint . -f json` + `scripts/sast-summary.mjs` |
| `sca-osv.png` | `docs/evidence/sca.txt` | `node scripts/sca-osv.mjs` |
| `ci-local.png` | `docs/evidence/ci-local.txt` | `scripts/ci-local.ps1` (the four `ci.yml` jobs) |
| `cve-exploit.png` | `docs/evidence/cve-vulnerable.txt` | `cve/exploit.ps1` against `vulhub/spring-webmvc:5.3.17` |
| `cve-fixed.png` | `docs/evidence/cve-fixed.txt` | `cve/verify-fix.ps1` against the Spring 5.3.18 build |

Reproduce any of them:

```powershell
python scripts/render_png.py docs/evidence/api-demo.txt docs/screenshots/api-demo.png `
    --title "scripts/demo.mjs - Work 1 API walkthrough" `
    --footer "Windows 11 / Node 24 / Express 5 + SQLite"
```

## What is deliberately *not* here

There is no screenshot of the GitHub Actions UI, because this repository has not
been pushed from the machine that produced these files. `ci-local.png` is a
faithful run of the same four jobs, labelled as a local run in the README and in
both reports. After the first push, add `actions-ci.png` (the green run page +
the `sast`/`sca` job summaries) and put the run URL in the README and on the
report title page. See `docs/SUBMISSION.md`.
