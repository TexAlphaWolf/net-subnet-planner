# Contributing

```bash
pip install -e ".[web,dev]"
ruff check . && ruff format --check . && mypy && pytest -n auto --cov
```

Changes to `netmath.py` need a test that compares against brute force or the standard library, as the existing ones do.
Claims in the docs are checked against `docs/report.json` by `tests/test_docs.py`; re-run `python tools/evaluate.py` and
update the text when numbers change.
