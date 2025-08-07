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
   In the root directory, create a certs folder and generate an OIDC client. Add the onboard client’s key to the oidckeystore.p12 file and place this file inside the certs folder.
   Refer to the [official documentation](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers) for guidance on how to create the **oidckeystore.p12** file and add the OIDC client key to it.
   * The **oidckeystore.p12** file stores keys and certificates, each identified by an alias (e.g., mpartner-default-mimoto-insurance-oidc). Mimoto uses this alias to find the correct entry and access the corresponding private key during the authentication flow.
   * Update the **client_alias** field in the [mimoto-issuers-config.json](src/main/resources/mimoto-issuers-config.json) file with this alias so that Mimoto can load the correct key from the keystore.
   * Also, update the **client_id** field in the [same file](src/main/resources//mimoto-issuers-config.json) with the client_id used during the onboarding process.
   * Set the `oidc_p12_password` environment variable in the Mimoto service configuration inside docker-compose.yml to match the password used for the **oidckeystore.p12** file.
   * Update the following properties in applicatio-local.properties file
   ```properties
   mosip.oidc.p12.password=<your-keystore-password>
   mosip.kernel.keymanager.hsm.config-path=<path to the keystore file>
   mosip.kernel.keymanager.hsm.keystore-pass=<your-keystore-password>
    ```
   * Mimoto also uses this same keystore file (oidckeystore.p12) to store keys generated at service startup, which are essential for performing encryption and decryption operations through the KeyManager service.

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

## [Deployment in K8 cluster](deploy/README.md)

## Credits
Credits listed [here](/Credits.md)
