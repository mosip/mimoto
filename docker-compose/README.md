## Overview

This is the docker-compose setup to run mimoto which act as BFF for Inji mobile and backend for Inji web. This is not for production use.

## What is in the docker-compose folder?

1. certs folder holds the p12 file which is being created as part of OIDC client onboarding.
2. "config" folder holds the mimoto system properties file, issuer configuration and credential template.
3. "docker-compose.yml" file with mimoto setup.


## How to run this setup?
1. Refer to the [How to create Google Client Credentials](#how-to-create-google-client-credentials) section to create
   Google client credentials and replace the below placeholders of Mimoto service in the `docker-compose.yml` file with the generated credentials:
   ```yaml
       environment:
         - GOOGLE_OAUTH_CLIENT_ID=<your-client-id>
         - GOOGLE_OAUTH_CLIENT_SECRET=<your-client-secret>
   ```
   
2. Add identity providers as issuers in the `mimoto-issuers-config.json` file of [docker-compose config folder](config/mimoto-issuers-config.json). For each provider, create a corresponding object with its issuer-specific configuration. Refer to the [Issuers Configuration](#mimoto-issuers-configuration) section for details on how to structure this file and understand each field's purpose and what values need to be updated.

3. Add or update the verifiers clientId, redirect and response Uris in `mimoto-trusted-verifiers.json` file of [docker-compose config folder](config/mimoto-trusted-verifiers.json) for Verifiable credential Online Sharing.

4. Create certs folder in the same directory and create OIDC client. Add key in oidckeystore.p12 and copy this file under certs folder.
   Refer [here](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers) to create client
   * Update **client_id** and **client_alias** as per onboarding in [mimoto-issuers-config.json](config/mimoto-issuers-config.json) file.
   * Update `oidc_p12_password` environment variable of Mimoto service in docker-compose.yml to match the password set for the oidckeystore.p12 file.
   * Mimoto uses this same keystore file (oidckeystore.p12) to store keys generated at service startup, which are essential for performing encryption and decryption operations through the KeyManager service.
   
5. To configure any Mobile Wallet specific configurations refer to the [Inji Mobile Wallet Configuration](#inji-mobile-wallet-configuration) section.

6. Choose your setup for starting the services:
   - **Starting all services via Docker Compose (including Mimoto):**
   Run the following command to start the services
   ```bash
      docker-compose up
   ```
   - **Running Mimoto in IDE and other services like `datashare service` via Docker Compose:**
   1.  In `docker-compose.yml`, update the `DATASHARE_DOMAIN` environment variable for the `Datashare service` to `localhost:8097`.
   2.  Then, start your dependent services by running the following command
   ```bash
      docker-compose up # Use this to comment inji web service and start all the other services defined in docker-compose.yml
      # OR
      docker-compose up datashare other_service_name # To start specific services (replace with actual names)
   ```
   **Note:** Use the **-d** flag with docker-compose up to run the services in detached (background) mode.
   
7. To stop all the services, navigate to docker-compose folder and run the following command
   ```bash
   docker-compose down
   ```

8. To stop a specific service (e.g., mimoto-service) and remove its container and image, run the following commands
   ```bash
   docker-compose stop <service_name> # To stop a specific service container
   docker-compose rm <service_name> # To remove a specific service container
   docker rmi <image_name:tag> # To remove a specific service image
   ```

9. **Removing the Docker Volume:**
   - To remove the persistent data for a specific service within an application, you can delete its individual Docker volume. This is necessary in situations where you need to start fresh or when data has become corrupted.
   - For example, if you update the oidckeystore.p12 file, the mimoto service might fail to start. This happens because the new .p12 file may not contain the keys that are stored in the database's key alias table. Since these keys are used in the encryption and decryption flow, their absence prevents the service from functioning correctly. To fix this, you must remove the postgres-data volume to clear the old, encrypted data, which allows the service to start correctly with a new dataset.

   - Use the following command to remove the volume:
   ```Bash
   docker volume rm <volume_name> # E.g., docker volume rm docker-compose_postgres-data
   ```

10. Access Apis as
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

## 📄Mimoto Issuers Configuration

The mimoto-issuers-config.json file defines the list of Credential Issuers that support Verifiable Credential issuance using the OpenID4VCI protocol. Mimoto uses it to load Issuer metadata configuration like logo, client details and endpoints needed for initiating and completing credential issuance.

### 🧩Structure and example

```json
{
  "issuers": [
     {
        "issuer_id": "StayProtected",
        "credential_issuer": "StayProtected",
        "display": [
           {
              "name": "StayProtected Insurance",
              "logo": {
                 "url": "https://raw.githubusercontent.com/tw-mosip/file-server/master/StayProtectedInsurance.png",
                 "alt_text": "a square logo of a Sunbird"
              },
              "language": "en",
              "title": "Download StayProtected Insurance Credentials",
              "description": "Download insurance credential"
           }
        ],
        "protocol": "OpenId4VCI",
        "client_id": "esignet-sunbird-partner",
        "client_alias": "esignet-sunbird-partner",
        "wellknown_endpoint": "https://injicertify-insurance.collab.mosip.net/v1/certify/issuance/.well-known/openid-credential-issuer",
        "redirect_uri": "io.mosip.residentapp.inji://oauthredirect",
        "authorization_audience": "https://esignet-insurance.collab.mosip.net/v1/esignet/oauth/v2/token",
        "token_endpoint": "https://localhost:8099/v1/mimoto/get-token/StayProtected",
        "proxy_token_endpoint": "https://esignet-insurance.collab.mosip.net/v1/esignet/oauth/v2/token",
        "qr_code_type": "OnlineSharing",
        "credential_issuer_host": "https://injicertify-insurance.collab.mosip.net",
        "enabled": "true"
     }
  ]
}
```

### Issuer configuration field Descriptions

| Field                    | Description                                                                                                                                                                      | Value                                                                                                                                                                                                                                         | Required  |
| ------------------------ |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| `issuer_id`              | Unique identifier for the Issuer                                                                                                                                                 | Use your own Issuer's name, e.g., `"HealthInsuranceIssuer"`                                                                                                                                                                                   | Mandatory |
| `credential_issuer`      | Logical name (usually the same as `issuer_id`)                                                                                                                                   | Same as above or a recognizable alias                                                                                                                                                                                                         | Mandatory |
| `display[]`              | A list of display configurations, one per supported language. Each object includes localized fields like `name`, `logo.url`, `logo.alt_text`, `language`, `title`, `description` | Provide user-facing display metadata such as Issuer name, logo, and descriptions. You can customize existing entries or add new ones for each supported language                                                                              | Mandatory |
| `protocol`               | Protocol used; must be `"OpenId4VCI"`                                                                                                                                            | Do not change unless the protocol evolves                                                                                                                                                                                                     | Mandatory |
| `client_id`              | OAuth client ID registered with the Issuer during onboarding                                                                                                                     | Replace with the client ID provided when onboarding Issuer with the Issuer’s authorization server                                                                                                                                             | Mandatory |
| `client_alias`           | Internal alias for the Issuer (e.g., used to fetch secure credentials of Issuer from keystore file `oidckeystore.p12`)                                                           | Set this to the alias value provided while inserting an entry for the Issuer into oidckeystore.p12 file during Issuer onboarding                                                                                                              | Mandatory |
| `wellknown_endpoint`     | URL to the Issuer's `.well-known/openid-credential-issuer` endpoint as per OpenID4VCI spec                                                                                       | Replace with your Issuer’s actual metadata endpoint to discover important configuration details about the Credential Issuer                                                                                                                   | Mandatory |
| `redirect_uri`           | OAuth2 redirect URI of your app where users are sent after authentication; must match one registered with the Issuer's authorization server                                      | Replace with one of the URI's that were registered during Issuer onboarding on the authorization server                                                                                                                                       | Mandatory |
| `authorization_audience` | Audience value for token requests                                                                                                                                                | Usually the base URL of the Issuer’s token service                                                                                                                                                                                            | Mandatory |
| `token_endpoint`         | Internal proxy token endpoint provided by Mimoto to forward requests to the real Auth server and it should be HTTPS URL                                                          | Use an internal/exposed domain or an ngrok URL if testing locally with the Inji mobile wallet                                                                                                                                                 | Mandatory |
| `proxy_token_endpoint`   | Actual token endpoint of the Authorization server                                                                                                                                | Replace with the Auth server's token endpoint URL                                                                                                                                                                                             | Mandatory |
| `qr_code_type`           | Type of QR code: `"OnlineSharing"` or `"EmbeddedVC"`                                                                                                                             | Use `"OnlineSharing"` to embed the OpenID4VP authorization request in a Verifiable Credential PDF QR code for verifiers to verify it. Use `"EmbeddedVC"` to embed the entire Verifiable Credential in the QR code (typically for offline use) | Optional  |
| `credential_issuer_host` | Host/domain of the credential Issuer                                                                                                                                             | Replace with your Issuer's domain                                                                                                                                                                                                             | Mandatory |
| `enabled`                | Enables or disables this Issuer configuration                                                                                                                                    | Set to `"false"` to disable or hide this Issuer                                                                                                                                                                                               | Mandatory |

### ✅ How to Add a New Issuer

1. Add a new Issuer object in the mimoto-issuers-config.json file using the structure, field descriptions, and example provided above.
2. Ensure:
   - All the configured endpoints for the Issuer and its Authorization server are reachable and functional.
   - `redirect_uri` matches one of the URIs registered with the Issuer’s Authorization server during Issuer onboarding.
   - `client_id` matches the one provided during Issuer onboarding with the Issuer's Authorization server.
   - `client_alias` for each Issuer is correctly configured and available in the oidckeystore.p12 file.
3. For step-by-step guidance on how to add a new Issuer and generate the oidckeystore.p12 file, refer to the [Customization Overview](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers) documentation.

## Inji Mobile Wallet Configuration
To bind an Android or iOS wallet using the e-signet service via Mimoto, ensure the following property is updated in application-local.properties (if running Mimoto using IDE) or mimoto-default.properties (if running Mimoto using docker compose) to point to the appropriate e-signet instance running in your target environment
```properties
    mosip.esignet.host=<Host url of e-signet service> (E.g. https://esignet.env.mosip.net)
```

Note:
- Replace mosipbox.public.url, mosip.api.public.url with your public accessible domain. For dev or local env [ngrok](https://ngrok.com/docs/getting-started/) is recommended.
