# CI and release checks

Run the complete local release gate with:

```sh
make release-check
```

It checks formatting, unit tests, static analysis, race detection, dependency
integrity, and the Docker-backed PostgreSQL 15–17 integration matrix.

GitHub Actions runs the standard verification target on every push and pull
request. CI must provide a running Docker daemon for the integration matrix.
