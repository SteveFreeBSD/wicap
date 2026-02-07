# Reports Governance

This folder is the only place for WICAP reports. It prevents duplicated,
conflicting status files scattered across the repo.

## Where Reports Live

- Soak reports: `docs/reports/soak/`
- Reviews/audits: `docs/reports/`

If a report needs data from logs, keep logs under `logs/` and reference them in
the report rather than copying raw log output into docs.

## Naming + Versioning

- Use date-stamped filenames: `report_YYYY-MM-DD.md` or
  `soak_YYYYMMDD_hhmm.md`
- If a report is updated, **edit the existing file** and add an "Update" section
  with the new timestamp rather than creating a second competing report.

## What Not To Do

- Do not add new roadmap files. Update `docs/ROADMAP.md`.
- Do not write reports outside `docs/reports/`.
- Do not create duplicate checklists in other folders. Use
  `docs/reports/soak/` and link to `docs/TESTING.md` for commands.
