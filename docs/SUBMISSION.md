# Before you submit — publish the repository

Everything in this folder is complete and locally verified. The reports already
carry the student's name (Wu ZiYang) and HDU number (23320121); no variant was
assigned, so the variant field is "—". The only remaining step is to publish the
project, which makes the repository and pipeline links real:

| # | Item | Action |
|---|---|---|
| 1 | `https://github.com/faris-faris-faris/work1-secure-notes-api` | push the project so this URL exists |
| 2 | `https://github.com/faris-faris-faris/work1-secure-notes-api/actions` | copy the URL of the **last successful run** after the first push |
| 3 | `docs/screenshots/ci-local.png` | optionally replace with a screenshot of the green **Actions** run |

Files that contain the repository URL:

* `README.md` — header and submission section;
* `docs/report_en.md`, `docs/report_zh.md` — title page and §7;
* `docs/SUBMISSION.md` — this file.

## 1. Publish the repository

```bash
cd work1-secure-notes-api
git init
git add .
git commit -m "feat: secure notes API, CI with SAST/SCA, CVE-2022-22965 study"
git branch -M main
git remote add origin https://github.com/faris-faris-faris/work1-secure-notes-api.git
git push -u origin main
```

With the GitHub CLI:

```bash
gh repo create work1-secure-notes-api --public --source . --remote origin --push
```

The workflow starts on the first push. All four jobs must be green; the run
takes about a minute.

## 2. Capture the pipeline evidence

1. Open **Actions → ci → the latest run**.
2. Screenshot the job list (four green jobs) **and** the `sast` / `sca` job
   logs, or download their artifacts.
3. Copy the run URL — that is field 2 above.
4. Save the screenshot as `docs/screenshots/actions-ci.png` and add it to both
   reports (the Markdown already shows `ci-local.png`; add the Actions image
   next to it, or replace it).

## 3. Rebuild the PDFs

```bash
python scripts/build_report.py --pdf docs/report_en.md docs/report_zh.md
```

## 4. What the marker receives

```
work1-secure-notes-api/            the repository (code, tests, CI, cve/, reports)
work1-Wu-submission.zip            this folder, zipped
```

The zip contains the reports as PDF and Markdown, the evidence transcripts
(`docs/evidence/`), the screenshots (`docs/screenshots/`) and the patched
environment (`cve/Dockerfile.fixed`, `cve/docker-compose.fixed.yml`).

## Honest labelling of the CI evidence

`ci-local.png` is a real run of the exact commands in `.github/workflows/ci.yml`
on this machine (`scripts/ci-local.ps1`). It is labelled as such in the README
and in both reports. It is **not** a screenshot of GitHub's UI, and the reports
do not claim that a pipeline has run on GitHub. Replace it after the first push
so the submitted evidence matches field 2.
