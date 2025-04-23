[![Maven Package upon a push](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml/badge.svg?branch=master)](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mimoto&id=mosip_mimoto&metric=alert_status)](https://sonarcloud.io/project/overview?id=mosip_mimoto)

# mimoto

## Overview
This repository contains source code for backend service of Inji Mobile and Inji Web. The modules exposes API endpoints.


## Build & run (for developers)
The project requires JDK 21, postgres, redis and google client credentials
### without docker-compose Build & install
1. Install pgadmin, redis and update application-local.properties file with values 
   ```
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
3. Run the SQLs using <db name>/deploy.sh script. from [db_scripts folder](db_scripts/inji_mimoto)
   ```
   ./deploy.sh deploy.properties
   ```
4. Build the jar
    ```
    mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true
    ```
5. Run following command 
    ```
    mvn spring-boot:run -Dspring.profiles.active=local
    ```
### with docker-compose
1. To simplify running mimoto in local for developers we have added [Docker Compose Setup](docker-compose/README.md). This docker-compose includes mimoto service and nginx service to server static data.
2. Follow the below steps to use custom build image in docker-compose
* Build the mimoto.jar
  ```mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true```
* Build docker image, use any image tag
  ```docker build -t <image-with-tag> .```
* Use newly built docker image in docker-compose file


## Credits
Credits listed [here](/Credits.md)
