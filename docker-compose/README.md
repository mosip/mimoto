## Overview

This is the docker-compose setup to run mimoto which act as BFF for Inji mobile and backend for Inji web. This is not for production use.

## What is in the docker-compose folder?

1. certs folder holds the p12 file which is being created as part of OIDC client onboarding.
2. "config" folder holds the mimoto system properties file, issuer configuration and credential template.
3. "docker-compose.yml" file with mimoto setup.


## How to run this setup?

1. Add Id providers as issuers in mimoto-issuers-config.json. For each provider, include the token_endpoint property, which should be an HTTPS URL. This can either be an exposed domain or, for local setups, an ngrok URL if you're using mimoto for local testing with the Inji mobile wallet.

2. Add verifiers clientId and redirect Uris in mimoto-trusted-verifiers.json for Online Sharing

3. Start esignet services and update esignet host references in mimoto-default.properties and mimoto-issuers-config.json

4. Create certs folder in the same directory and create OIDC client. Add key in oidckeystore.p12 and copy this file under certs folder.
Refer [here](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers) to create client
* Update client_id and client_alias as per onboarding in mimoto-issuers-config.json file.
* Update oidc_p12_password in docker-compose.yml to match the password set for the oidckeystore.p12 file.
5. Refer to the [How to create Google Client Credentials](#how-to-create-google-client-credentials) section to create 
    Google client credentials.
   - Replace the placeholders in the `docker-compose.yml` file with the generated credentials:

   ```yaml
       environment:
         - GOOGLE_OAUTH_CLIENT_ID=<your-client-id>
         - GOOGLE_OAUTH_CLIENT_SECRET=<your-client-secret>

6. Start the services using docker-compose
    - If you are running Mimoto using docker compose, then use the following command
    ```bash
        docker-compose up
    ```
    - If you are running Mimoto locally and the other services (like Datashare service) using Docker Compose, then use the following command to override the SHARE_DOMAIN property of Datashare service
    ```bash
       docker-compose -f docker-compose.yml -f docker-compose.local.yml up
    ```

7. Access Apis as
   * http://localhost:8099/v1/mimoto/allProperties
   * http://localhost:8099/v1/mimoto/issuers
   * http://localhost:8099/v1/mimoto/issuers/StayProtected
   * http://localhost:8099/v1/mimoto/issuers/StayProtected/well-known-proxy

## How to create Google Client Credentials

To enable Google OAuth2.0 authentication, follow these steps:

1. **Go to the Google Cloud Console**:
   - Visit [Google Cloud Console](https://console.cloud.google.com/).

2. **Create a New Project**:
   - If you don’t already have a project, create a new one by clicking on the project dropdown and selecting "New Project".

3. **Enable the OAuth Consent Screen**:
   - Navigate to "APIs & Services" > "OAuth consent screen".
   - Select "External" for the user type and configure the required fields (e.g., app name, support email, etc.).
   - Save the changes.
4. **Create OAuth 2.0 Credentials**:
   - Navigate to "APIs & Services" > "Credentials".
   - Click "Create Credentials" > "OAuth 2.0 Client IDs".
   - Select "Web application" as the application type.

5. **Configure Authorized JavaScript Origins**:
   Depending on your environment, use the following values:

   - **Local or Docker**:
     ```
     http://localhost:8099
     ```
   - **Deployed domain (e.g., collab.mosip.net)**:
     ```
     https://collab.mosip.net

6. **Configure Authorized Redirect URIs**:
   - **Local or Docker**:
     ```
     http://localhost:8099/v1/mimoto/oauth2/callback/google
     ```
   - **Deployed domain (e.g., collab.mosip.net)**:
     ```
     https://collab.mosip.net/v1/mimoto/oauth2/callback/google
     ```

7. **Save and Retrieve Client Credentials**:
   - After saving, you will receive a `Client ID` and `Client Secret`.

Note:
- Replace mosipbox.public.url, mosip.api.public.url with your public accessible domain. For dev or local env [ngrok](https://ngrok.com/docs/getting-started/) is recommended.
