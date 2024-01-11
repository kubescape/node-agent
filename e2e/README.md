# E2E Tests

E2E tests for `node-agent` component are made by running the following steps:

* initializing a **KinD** cluster locally
* installing dependencies (`ginkgo`, `helm`, additional repositories, etc) 
* installing the minimum amount of componentes in order to make the `node-agent` works (`operator`, `storage`)
* running the **e2e** test suite using `ginkgo`.

## Prerequisites

There are only few dependencies in order to be able to run the test suite. Here's the list:

* `go`
* `git`
* `kind`

## Getting Started

All these steps can easily be covered by typing these commands:

* `make e2e/v<kubernetes_version>` (eg. `make e2e/v1.27.3`): run the whole test suite using a specific kubernetes version (this will allow us to test `node-agent` with multiple kuberentes versions)
* `make e2e-destroy` to clean up the testing enironment

