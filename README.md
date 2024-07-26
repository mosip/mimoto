[![Maven Package upon a push](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml/badge.svg?branch=master)](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mimoto&id=mosip_mimoto&metric=alert_status)](https://sonarcloud.io/project/overview?id=mosip_mimoto)

# mimoto

## Overview
This repository contains source code for backend service of Inji Mobile and Inji Web. The modules exposes API endpoints.  


## Build & run (for developers)
The project requires JDK 11
### Build & install
```
    mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true
```

### Run
1. without docker-compose
```
    mvn spring-boot:run -Dspring.profiles.active=local
```

2. with docker-compose
   * To simplify running mimoto in local for developers we have added [Docker Compose Setup](docker-compose/README.md). This docker-compose includes mimoto service and nginx service to server static data.

   *  Follow the below steps to use custom build image in docker-compose
     * 
       * Build the mimoto.jar
       ```mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true```
       * Build docker image, use any image tag
       ```docker build -t <image-with-tag> .```
       * Use newly built docker image in docker-compose file
  
## Deployment

### Install

1. Execute inji-config-server install script
```
cd helm/inji-config-server
./install.sh
```
* Review values.yaml and make sure git repository parameters are as per your installation.

2. Execute Onboarder install script 

```
cd partner-onboarder
./install.sh
```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 and check the reports. There should not be any failures.

3. Execute mimoto install script

```
cd helm/mimoto
./install.sh
```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

### For Onboarding new Issuer for VCI:

- create a folder "certs" in the root and a file "oidckeystore.p12" inside certs and store the keys as different aliases for every issuers. for more details refer [here](https://docs.mosip.io/inji/inji-mobile-wallet/customization-overview/credential_providers)


## Credits
Credits listed [here](/Credits.md)
