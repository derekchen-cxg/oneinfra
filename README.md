| Go Report                                                                                                                                      | Travis                                                                                                             | CircleCI                                                                                                             | Azure Test                                                                                                                                                                                    | Azure Release                                                                                                                                                                                       | License                                                                                                                              |
|------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| [![Go Report Card](https://goreportcard.com/badge/github.com/oneinfra/oneinfra)](https://goreportcard.com/report/github.com/oneinfra/oneinfra) | [![Travis CI](https://travis-ci.org/oneinfra/oneinfra.svg?branch=master)](https://travis-ci.org/oneinfra/oneinfra) | [![CircleCI](https://circleci.com/gh/oneinfra/oneinfra.svg?style=shield)](https://circleci.com/gh/oneinfra/oneinfra) | [![Test Pipeline](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master)](https://dev.azure.com/oneinfra/oneinfra/_build/latest?definitionId=3&branchName=master) | [![Release Pipeline](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/release?branchName=master)](https://dev.azure.com/oneinfra/oneinfra/_build/latest?definitionId=4&branchName=master) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)|

# oneinfra

`oneinfra` is a Kubernetes as a Service platform. It empowers you to
provide or consume Kubernetes clusters at scale, on any platform or
service provider. You decide.

|                                               |                                                     |
|-----------------------------------------------|-----------------------------------------------------|
| ![Cluster list](screenshots/cluster-list.png) | ![Cluster details](screenshots/cluster-details.png) |

[Read more about its design here](docs/DESIGN.md).


## Managed Kubernetes versions

| Kubernetes version | Deployable with      | Default in           |                                                                                                                                                                            |                                                                                                                                                                             |
|--------------------|----------------------|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `1.15.12`          | `20.05.0-alpha14` |                      | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.15.12)%20with%20local%20CRI%20endpoints)        | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.15.12)%20with%20remote%20CRI%20endpoints)        |
| `1.16.9`           | `20.05.0-alpha14` |                      | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.16.9)%20with%20local%20CRI%20endpoints)         | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.16.9)%20with%20remote%20CRI%20endpoints)         |
| `1.17.5`           | `20.05.0-alpha14` |                      | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.17.5)%20with%20local%20CRI%20endpoints)         | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.17.5)%20with%20remote%20CRI%20endpoints)         |
| `1.18.2`           | `20.05.0-alpha14` | `20.05.0-alpha14` | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.18.2)%20with%20local%20CRI%20endpoints)         | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.18.2)%20with%20remote%20CRI%20endpoints)         |
| `1.19.0-alpha.3`   | `20.05.0-alpha14` |                      | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.19.0-alpha.3)%20with%20local%20CRI%20endpoints) | ![Build Status](https://dev.azure.com/oneinfra/oneinfra/_apis/build/status/test?branchName=master&jobName=e2e%20tests%20(1.19.0-alpha.3)%20with%20remote%20CRI%20endpoints) |


## Install

The `oneinfra` installation has several components:

* `oi`: `oneinfra` main CLI tool. This binary allows you to join new
  worker nodes, generate administrative kubeconfig files...

* `oi-local-hypervisor-set`: allows you to create fake hypervisors
  running as docker containers. This command is only meant to be used
  in test environments, never in production.

* `oi-manager` is `oneinfra`'s Kubernetes controller manager. The
  `oi-manager` is released as a container image and published in the
  Docker Hub.

* `oi-console` is `oneinfra`'s web console [living in a separate
  repository](https://github.com/oneinfra/console). The `oi-console`
  is released as a container image and published in the Docker Hub. It
  is optional to deploy.


### From released binaries

```console
$ wget -O oi https://github.com/oneinfra/oneinfra/releases/download/20.05.0-alpha14/oi-linux-amd64-20.05.0-alpha14
$ chmod +x oi
$ wget -O oi-local-hypervisor-set https://github.com/oneinfra/oneinfra/releases/download/20.05.0-alpha14/oi-local-hypervisor-set-linux-amd64-20.05.0-alpha14
$ chmod +x oi-local-hypervisor-set
```

You can now move these binaries to any place in your `$PATH`, or
execute them with their full path if you prefer.

As an alternative you can [install from source if you
prefer](docs/install-from-source.md).


## Lightning-quick start

* Requirements
  * Docker
  * `kind`
  * `kubectl`
  * `oi-local-hypervisor-set`

On a Linux environment, execute:

```console
$ curl https://raw.githubusercontent.com/oneinfra/oneinfra/20.05.0-alpha14/scripts/demo.sh | sh
```

After the script is done, you will be able to access your `oneinfra`
demo environment in `http://localhost:8000` and log in with username
`sample-user` with password `sample-user`.


## Quick start

If you prefer to run the quick start yourself instead of the lightning
quick start, [follow the instructions here](docs/quick-start.md).


## Joining worker nodes to a managed cluster

You can read more details about the [worker joining process
here](docs/joining-worker-nodes.md).


## License

`oneinfra` is licensed under the terms of the Apache 2.0 license.

```
Copyright (C) 2020 Rafael Fernández López <ereslibre@ereslibre.es>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
