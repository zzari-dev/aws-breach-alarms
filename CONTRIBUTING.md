# Contributing

Bug reports, false-positive reports and new rules are welcome.

## Adding or changing a rule

Write the test first.

1. Add CloudTrail events under `tests/events/<slug>/match/` and `tests/events/<slug>/nomatch/`.
   - Use documentation values only: account `123456789012` and IPs from `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`.
   - Never paste real events without scrubbing them.
2. Run `make test` and watch the new cases fail.
3. Add or edit `rules/<id>-<slug>.json`. Use `@@param@@` tokens for configurable values and declare them in `params`.
4. Add a section to `docs/runbook.md` and `docs/runbook.ko.md`.
5. Run `make build` to regenerate the CloudFormation template, then `make all`.
6. Add a line to `CHANGELOG.md`.

Narrowing a pattern or renaming a rule can silently drop alerts for existing users. It is a breaking change.

## Development

Requirements:
- Java 17+ (for aws/event-ruler)
- [uv](https://docs.astral.sh/uv/)
- Terraform 1.5+

```sh
make test            # offline: patterns, catalog, CloudFormation
make test-terraform  # plans the module with fake credentials
make verify-aws      # optional: cross-check with the real EventBridge API
```
