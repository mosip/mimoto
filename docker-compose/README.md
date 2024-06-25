## Overview

This is the docker-compose setup to run mimoto which act as BFF for Inji mobile and backend for Inji web. This is not for production use.

## What is in the docker-compose folder?

1. certs folder holds the p12 file which is being created as part of OIDC client onboarding.
2. "config" folder holds the mimoto system properties file, issuer configuration and credential template.
3. "loader_path" this is mimoto mount volume from where all the runtime dependencies are loaded to classpath.
4. "docker-compose.yml" file with mimoto setup.


## How to run this setup?

1. Create loader_path folder in the same directory and Download the kernel auth adapter from [here](https://repo1.maven.org/maven2/io/mosip/kernel/kernel-auth-adapter/1.2.0.1/kernel-auth-adapter-1.2.0.1.jar). Copy the downloaded jar under loader_path directory and rename it to kernel-auth-adapter.jar

2. Add Id providers as an issuer in mimoto-issuers-config.json

3. Start esignet services and update esignet host references in mimoto-default.properties and mimoto-issuers-config.json

4. Create certs folder in the same directory and create OIDC client. Add key in oidckeystore.p12 and copy this file under certs folder.
Refer [here](https://docs.mosip.io/inji/inji-mobile-wallet/customization-overview/credential_providers) to create client
* Update client_id and client_alias in mimoto-issuers-config.json file.
* update p12 file password `mosip.oidc.p12.password` in mimoto-default.properties file.


5. Start the docker-compose file

> docker-compose up

7. Access Apis as
   * http://localhost:8099/residentmobileapp/allProperties
   * http://localhost:8099/residentmobileapp/issuers
   * http://localhost:8099/residentmobileapp/issuers/Sunbird
   * http://localhost:8099/residentmobileapp/issuers/Sunbird/credentialTypes


Note:
- For local env use [ngrok](https://ngrok.com/docs/getting-started/).
- Replace http://localhost:8099 by ngrok public domain at following places
  - token_endpoint in mimoto-issuers-config.json
  - mosipbox.public.url, mosip.api.public.url in mimoto-default.properties