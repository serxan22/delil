## Summary

<!-- What does this change and why? Link the issue it resolves. -->

## Checklist

- [ ] Tests cover the change (`make test`; database tests with `DELIL_TEST_DATABASE_URL`, see CONTRIBUTING.md)
- [ ] `make lint` passes
- [ ] Documentation updated (README, `docs/`, `api/openapi.yaml`, CHANGELOG `Unreleased`)
- [ ] No secrets, real personal data or credentials in code, tests or fixtures

## Integrity impact

<!-- Tick one. Anything that changes what is canonicalized, hashed or signed needs maintainer sign-off. -->

- [ ] None: this does not affect canonicalization, hashing, signing, verification or the evidence format
- [ ] Yes: explained below, with a schema-version bump and updated `docs/test-vectors.json`, and existing chains still verify
