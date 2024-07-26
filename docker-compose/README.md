## Overview

This is the docker-compose setup to run mimoto which act as BFF for Inji mobile and backend for Inji web. This is not for production use.

## What is in the docker-compose folder?

1. certs folder holds the p12 file which is being created as part of OIDC client onboarding.
2. "config" folder holds the mimoto system properties file, issuer configuration and credential template.
3. "loader_path" this is mimoto mount volume from where all the runtime dependencies are loaded to classpath.
4. "docker-compose.yml" file with mimoto setup.


## How to run this setup?

1. Create loader_path folder in the same directory and Download the kernel auth adapter from [here](https://repo1.maven.org/maven2/io/mosip/kernel/kernel-auth-adapter/1.2.0.1/kernel-auth-adapter-1.2.0.1.jar).  Copy the downloaded jar under loader_path directory.

2. Add Id providers as an issuer in mimoto-issuers-config.json

3. Start esignet services and update esignet host references in mimoto-default.properties and mimoto-issuers-config.json

4. Create certs folder in the same directory and create OIDC client. Add key in oidckeystore.p12 and copy this file under certs folder.
Refer [here](https://docs.mosip.io/inji/inji-mobile-wallet/customization-overview/credential_providers) to create client
* Update client_id and client_alias as per onboarding in mimoto-issuers-config.json file.

5. Start the docker-compose file

> docker-compose up

7. Access Apis as
   * http://localhost:8099/v1/mimoto/allProperties
   * http://localhost:8099/v1/mimoto/issuers
   * http://localhost:8099/v1/mimoto/issuers/Sunbird
   * http://localhost:8099/v1/mimoto/issuers/Sunbird/credentialTypes


Note:
- Replace mosipbox.public.url, mosip.api.public.url with your public accessible domain. For dev or local env [ngrok](https://ngrok.com/docs/getting-started/) is recommended.
