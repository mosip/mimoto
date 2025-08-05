# Deployment

## Pre-requisites
* Base infrastructure setup
   * Tool and utilities to be installed locally [steps](https://docs.inji.io/readme/setup/deploy#tools-and-utilities)
   * System Requirements: Hardware, network and certificate requirements [steps](https://docs.inji.io/readme/setup/deploy#system-requirements)
   * Set up Wireguard Bastion Host [steps](https://docs.inji.io/readme/setup/deploy#wireguard)
   * K8s Cluster setup [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-setup)
   * NGINX setup and configuration [steps](https://docs.inji.io/readme/setup/deploy#nginx-for-inji-k8-cluster)
   * K8s Cluster Configuration [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-configuration)
* inji-stack-config ConfigMap [steps](https://docs.inji.io/readme/setup/deploy#pre-requisites)
* Postgres installation [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/external/postgres)
* Config server secerts [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/mosip/conf-secrets)
* Config server installation [steps](https://docs.inji.io/readme/setup/deploy#config-server-installation)
* Artifactory installation [steps](https://github.com/mosip/artifactory-ref-impl/tree/v1.3.0-beta.2/deploy)

* Redis installation
```
cd deploy/redis
./install.sh
```
## Initialise pre-requisites
### [DB init](../db_scripts)
* Update values file for postgres init [here](../db_scripts/init_values.yaml).
````
   cd ../../db_scripts
  ./init_db.sh
```` 

## [Install Onboarder](../partner-onboarder)
* Execute Onboarder install script
```
cd ../partner-onboarder
./install.sh
 ```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 / NFS and check the reports. There should not be any failures.
* Note: If you are running the Onboarder in a separate INJI cluster, update the extraEnvVars section accordingly in [values.yaml](../partner-onboarder/values.yaml).

## Install mimoto
* Execute mimoto install script
* Before installing Mimoto, please ensure that the database host and port are correctly configured in the [values.yaml](mimoto/values.yaml) file.
```
cd ../deploy/mimoto
./install.sh
 ```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

### For Onboarding new Issuer for VCI:

- create a folder "certs" in the root and a file "oidckeystore.p12" inside certs and store the keys as different aliases for every issuers. for more details refer [here](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers)

## [mimoto apitestrig](mimoto-apitestrig)
