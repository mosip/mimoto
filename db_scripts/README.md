# Mimoto Database
Backend service of Inji Mobile and Inji Web. The modules exposes API endpoints.

## Overview
This folder contains SQL scripts to create databases and tables in postgres. The table structure is described under the `<db name>/ddl/` folder. Default data populated in the tables can be found in the `<db name>/dml` folder.

## Prerequisites
Before starting the installation, ensure the following:

1. **Command line utilities**:
    - `kubectl`: Kubernetes command-line tool.
    - `helm`: Kubernetes package manager.

2. **Helm Repositories**:
   Add the required Helm repositories to your environment:
   ```sh
   helm repo add bitnami https://charts.bitnami.com/bitnami
   helm repo add mosip https://mosip.github.io/mosip-helm
## Install in existing MOSIP K8 Cluster
These scripts are automatically run with below mentioned script in existing k8 cluster with Postgres installed.
### Install
* Set your kube_config file or kube_config variable on PC.
* Update `init_values.yaml` with db-common-password from the postgres namespace in the required field `dbUserPasswords.dbuserPassword` and ensure `databases.inji_mimoto` is enabled.
  ```
  ./init_db.sh`
  ```

## Install for developers
Developers may run the SQLs using `<db name>/deploy.sh` script.