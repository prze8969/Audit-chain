# CLAUDE.md: Operating contract for Audit-Chain
1. Do not web-search or browse. Everything needed is in this document. Items tagged [VERIFY-LOCAL] are confirmed by running the given local command, never by searching.
2. Work on exactly one checkpoint (CP) at a time. Run its check, show the output, and stop if it differs from the expected result. Do not start the next CP until the check passes.
3. Create no file, dependency, feature, rename or abstraction that is not in this document. If something seems missing, stop and ask.
4. Never guess library attributes. If an attribute is not listed here, print dir() of the object first and use only what exists.
5. All Cypher uses $params. The single exception is the hop bound of a variable-length pattern, which must be an int clamped to 1..8 and formatted into the string.
6. Python 3.11, type hints, single quotes, files under 200 lines, plain functions (classes only for Pydantic models).
7. A finding is valid only with a verified graph path. No path, no finding.
8. After each passing CP run git add -A and git commit with the CP number as the message.
9. Keep BUGS.md. Every failure found at any checkpoint is logged as: id, symptom, root cause, fix, and the CP or test that now guards it. Fix at the lowest layer first: ingestion, then tools, then verifier, then prompt.
10. Log every tool call (name, input, output, seconds) as one JSON line in reports/trace_<project>.jsonl.
