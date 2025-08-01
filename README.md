[![Maven Package upon a push](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml/badge.svg?branch=master)](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mimoto&id=mosip_mimoto&metric=alert_status)](https://sonarcloud.io/project/overview?id=mosip_mimoto)

# mimoto

## Overview
This repository contains source code for backend service of Inji Mobile and Inji Web. The modules exposes API endpoints.


## Build & run (for developers)
The project requires JDK 21, postgres, redis and google client credentials
### without docker-compose Build & install
1. Install pgadmin, redis and update application-local.properties file with values 
   ```properties
   spring.datasource.username=
   spring.datasource.password=
   spring.redis.password=
   ```
2. Refer to the [How to create Google Client Credentials](docker-compose/README.md#how-to-create-google-client-credentials) section to create
   Google client credentials and update below properties in `application-local.properties`.
    ``` 
    spring.security.oauth2.client.registration.google.client-id=
    spring.security.oauth2.client.registration.google.client-secret=
    ```
3. Add identity providers as issuers in the `mimoto-issuers-config.json` file of [resources folder](src/main/resources/mimoto-issuers-config.json). For each provider, create a corresponding object with its issuer-specific configuration. Refer to the [Issuers Configuration](docker-compose/README.md#mimoto-issuers-configuration) section for details on how to structure this file and understand each field's purpose and what values need to be updated.
4. Add or update the verifiers clientId, redirect and response Uris in `mimoto-trusted-verifiers.json` file of [resources folder](src/main/resources/mimoto-trusted-verifiers.json) for Verifiable credential Online Sharing.
5. Keystore(oidckeystore.p12) Configuration:
   * Create a folder named `certs` in the root directory of the project and place your PKCS#12 keystore file(oidckeystore.p12) which is being created as part of OIDC client onboarding. Refer to this https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers documentation to get the instructions on how to generate the keystore file. 
   * After adding keystore file update the following properties in application-local.properties file.
    ```properties
    mosip.oidc.p12.password=<your-keystore-password>
    mosip.kernel.keymanager.hsm.config-path=<path to the keystore file>
    mosip.kernel.keymanager.hsm.keystore-pass=<your-keystore-password>
    ```
   * Update client_id and client_alias for Issuer as per onboarding in [mimoto-issuers-config.json](src/main/resources/mimoto-issuers-config.json) file.
6. To configure any Mobile Wallet specific configurations refer to the [Inji Mobile Wallet Configuration](docker-compose/README.md#inji-mobile-wallet-configuration) section.
7. Run the SQLs using <db name>/deploy.sh script. from [db_scripts folder](db_scripts/inji_mimoto)
   ```
   ./deploy.sh deploy.properties
   ```
8. Build the jar
    ```
    mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true
    ```
9. Run following command 
    ```
    mvn spring-boot:run -Dspring.profiles.active=local
    ```

### with docker-compose
1. To simplify running mimoto in local for developers we have added [Docker Compose Setup](docker-compose/README.md). This docker-compose includes mimoto service and nginx service to server static data.
2. Follow the below steps to use custom build image in docker-compose
* Build the mimoto.jar
  ```mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true```
* Build docker image by running the below command in the directory where Dockerfile is present, use any image tag
  ```docker build -t <image-with-tag> .```
* Use newly built docker image in docker-compose file


## Credits
Credits listed [here](/Credits.md)
