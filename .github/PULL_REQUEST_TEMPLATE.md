<!--
Thanks for the PR! Two things make reviews fast:
1. A clear summary of WHAT changed and WHY.
2. The verification story — what you ran, what the result was.

Delete sections that don't apply. Drafts are welcome.
-->

## Summary

<!-- 1–3 bullet points. What changed? Why is it needed? -->

-

## Linked issue

<!-- "Closes #123" / "Refs #456". Open an issue first for anything non-trivial. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking, fixes an issue)
- [ ] Feature (non-breaking, adds capability)
- [ ] Breaking change (CLI / output shape / config schema change)
- [ ] Documentation
- [ ] CI / build / infra
- [ ] CTI-data / bundled-feeds update

## Verification

Paste the result of the full gate (or note why a step was skipped):

```
pytest tests/ -q                                                   →
ruff check threat_intel_hunter.py conftest.py src/ tests/ scripts/ →
python scripts/regen_examples.py --check                           →
```

<!-- If the byte-oracle drifted intentionally, regenerate AND commit the
     showcase bundle in this PR. -->

## Manual / scenario testing

<!-- For UX or output-shape changes: what command did you run, what did you
     see? Screenshots welcome for wizard / Web UI. -->

## Checklist

- [ ] README updated if user-visible behaviour changed
- [ ] CHANGELOG.md entry under **[Unreleased]**
- [ ] Tests added/updated (regression lock for fixes, happy + edge for features)
- [ ] No new runtime dependencies (or: justification noted in `tasks/todo.md`)
- [ ] No secrets, real IOCs, or TLP:AMBER+ material in the diff
- [ ] I have read [`CONTRIBUTING.md`](../CONTRIBUTING.md)
