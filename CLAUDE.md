## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. Route only to skills in the session's available-skills list; answer directly for quick questions or small scoped edits.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate, unless one read-only check confirms the cause and a narrow fix (then fix it and run the focused test)
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
- Author a backlog-ready spec/issue → invoke /spec

## Testing

- Module tests (Odoo test framework), Odoo 16, 17, 18, 19 and 20 from source, in parallel:
  `ODOO_SRC=/home/paseo/odoo-src DB_USER=paseo tools/run_tests.sh`
  (`ODOO_SRC` holds `odoo-<version>/` checkouts and `venv-<version>/` virtualenvs.)
- Tests live in `fivenines_monitoring/tests/` (`test_lib.py` pure units, `test_push.py`
  against the stub in `tests/stub_server.py`). CI runs the same suite on the official
  `odoo:<version>` Docker images (`.github/workflows/ci.yml`).
- End-to-end on a real server: `tools/e2e_local.py` (see README).
- When writing new functions, write a corresponding test; when fixing a bug, write a
  regression test; never commit code that makes existing tests fail.
