# CI and version tooling

This imports upstream's shell tooling and CI updates from the v0.9.2 baseline (`0691ffd`).
It changes build and release maintenance, without changing provider reconciliation or CRD schemas.

The main upstream reference is issue
[669](https://github.com/ionos-cloud/cluster-api-provider-proxmox/issues/669), split into
[PR 765](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/765) for the scripts and tests,
and [PR 766](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/766) for version CI.
[PR 847](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/847) adds synchronization of
the Go CI image.
[PR 704](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/704) splits reusable E2E workflows.

## Usage

Run scripts from the repository root. They require Bash, Go and Mike Farah's `yq` v4.
The Go bumper also requires Docker Buildx to resolve the CI image digest, unless a digest is supplied.

```sh
make verify-versions
hack/bump-go.sh 1.26.10
hack/bump-capi.sh v1.12.11
hack/bump-k8s.sh v0.34.11
hack/bump-golangci-lint.sh v2.11.4
hack/release.sh 1.3.5
```

These are maintenance examples using the current dependency baseline. The CAPI module version here is
independent of the version deployed on the management cluster. Changing dependencies requires reviewing
their compatibility and rerunning the normal checks.

`hack/auto-bump.sh` repairs related references after a dependency update; inspect its diff before committing.
None of these scripts commits, tags, pushes, publishes a release, or deploys a controller.
`release.sh` updates clusterctl and Sonar version references, adding a release series and E2E development
version when moving to a new minor series. The existing tag-triggered draft release workflow is retained.

Envtest now derives its Kubernetes minor from the effective `k8s.io/api` module version. It can still be
overridden, for example with `make test ENVTEST_K8S_VERSION=1.34.0` to reuse locally installed assets.

## Fork adaptations

- Version checks and Go/shell CI also run on `release/**` pushes, where this fork is developed.
- CAPMOX release references are aligned to v1.3.4; the E2E development version remains v1.3.99.
- The Go bumper preserves and updates the Dockerfile's exact patch pin, rather than retaining an old suffix.
  Upstream's minor-only Docker tags remain supported by the same helper and tests.
- The ignored `.tool-versions` file remains local configuration; maintain it separately if using asdf.

Upstream's action pins, shell coverage jobs and reusable E2E workflows are retained. E2E still requires
the `capmox-e2e` runner, its protected environment and Proxmox credentials; no live E2E run is started here.
GitHub-hosted execution of the workflows must be checked after pushing.

## Local checks

```sh
make lint-sh
make test-sh
make verify-versions
make lint verify test
```

Shell tests use ShellSpec v0.28.1; `make test-sh` also requires kcov. To run without coverage, use
`cd hack/spec && shellspec`. The tests operate on temporary fixture copies, not the repository's versions.
