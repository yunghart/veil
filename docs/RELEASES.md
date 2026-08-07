# Release procedure

Veil's release process separates three ideas that are often conflated:

1. **Tests** show that the checked code behaves as expected for covered cases.
2. **Reproducible builds** make it easier to compare artifacts built from the same source/toolchain.
3. **Cryptographic provenance/signatures** help show which source/build workflow produced an artifact.

None of them is a security audit.

## Maintainer procedure

From a clean `main` checkout:

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check .
```

Commit the release changes and push `main`. Wait for the `test` workflow to pass.

If you have Git signing configured, create a signed annotated tag:

```bash
git tag -s v0.2.0 -m 'Veil IM 0.2.0'
git push origin v0.2.0
```

If you do not yet have a signing key configured, an ordinary annotated tag can trigger the workflow, but do not describe that tag itself as cryptographically signed:

```bash
git tag -a v0.2.0 -m 'Veil IM 0.2.0'
git push origin v0.2.0
```

The `release` GitHub Actions workflow:

- verifies that the tag matches `pyproject.toml`
- runs tests and lint
- builds the wheel
- builds the simple binary `.deb`
- builds a source ZIP from the tagged Git tree
- verifies a same-run second `.deb` build has the same SHA-256 digest
- writes SHA-256 checksums
- requests GitHub build-provenance attestations for the artifacts
- creates the GitHub Release and uploads the artifacts

## Local reproducibility check

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
rm -rf /tmp/veil-a /tmp/veil-b
mkdir -p /tmp/veil-a /tmp/veil-b
OUT_DIR=/tmp/veil-a ./scripts/build-binary-deb.sh
OUT_DIR=/tmp/veil-b ./scripts/build-binary-deb.sh
sha256sum /tmp/veil-a/*.deb /tmp/veil-b/*.deb
```

Matching hashes on one machine/toolchain are a useful smoke check. Strong reproducible-build claims require independent builders and documented toolchain/environment constraints.

## Versioning rule

Veil 0.x protocol changes may be intentionally incompatible. Do not add silent downgrade behavior to make old peers connect.
