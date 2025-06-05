# Google OAuth2 Login Integration Guide

## Overview
This documentation explains the implementation of the login feature using Google OAuth2 login. It also covers the authentication mechanism for APIs in : 
 - `UsersController`
 - `WalletController`
 - `WalletCredentialsController`.

---

## Prerequisites
Before you begin, ensure you have:
1. **A Google Developer Console account.**
2. **A project created in the Google Developer Console.**
3. **OAuth2 enabled for the project.**
4. **A Client ID and Client Secret generated.**
---

## Google OAuth2 Integration Steps

1. **Configure OAuth2 Login**:
    - Google client ID and secret in `application-default.properties`:
      ```
      spring.security.oauth2.client.registration.google.client-id=${mosip.injiweb.google.client.id}
      spring.security.oauth2.client.registration.google.client-secret=${mosip.injiweb.google.client.secret}
      ```
Make sure value of `mosip.injiweb.google.client.id` and `mosip.injiweb.google.client.secret` are set in the environment.
2. **Authorized Host URL**:
    - Register the base domain of your mimoto in Google Developer Console, e.g., `https://your-mimoto-domain`.

3. **Redirect URI**:
    - Under Authorized redirect URIs in Google Developer Console, add:
      `https://<your-mimoto-domain>/oauth2/callback/*`
      Replace `<your-mimoto-domain>` with your application's domain.
    - Ensure the redirect URI matches the one configured in the Google Developer Console.
---
## Sequence Diagram
### Google Login Flow
```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Application
    participant GoogleOAuth2

    User->>Browser: Navigate to Login Page
    Browser->>Application: Request Login
    Application->>GoogleOAuth2: Redirect to Google Login
    GoogleOAuth2->>User: Prompt for Credentials
    User->>GoogleOAuth2: Enter Credentials
    GoogleOAuth2->>Application: Validate Access Token
    Application->>Browser: Redirect to Dashboard
    Browser->>User: Display Dashboard
 ```    
### Authenticated API Access Flow
```mermaid
 sequenceDiagram
    participant User
    participant Browser
    participant Application
    participant Redis

    User->>Browser: Request API
    Browser->>Application: Send API Request with Session ID
    Application->>Redis: Validate Session ID
    Redis->>Application: Return User Metadata
    Application->>Browser: Respond with Data
```
---
## Key Points
### Session-Based Authentication:
- On successful login, a session ID is generated and stored in Redis.
- All APIs in UsersController, WalletController, and WalletCredentialsController validate the session ID stored in Redis.

### Integration Points in Application
### Component	Responsibility

| **Component**                  | **Responsibility**                                                                 |
|--------------------------------|-------------------------------------------------------------------------------------|
| `Config`                       | Configures OAuth2 login, session management, and security settings.                |
| `OAuth2AuthenticationSuccessHandler` | Handles successful authentication, stores user metadata in the session, and redirects to the dashboard. |
| `OAuth2AuthenticationFailureHandler` | Handles authentication failures, logs errors, and redirects to the login page with error details. |
| `CustomOAuth2UserService`      | Retrieves and processes user information from the OAuth2 provider.                 |
| `TokenAuthController`          | Provides API for token-based authentication and session creation.                  |
| `UsersController`              | Manages user profile retrieval using session-based authentication.                 |
| `WalletsController`            | Handles wallet creation, unlocking, and deletion using session-based authentication. |
| `WalletCredentialsController`  | Manages credential download, retrieval, and deletion for wallets.                  |---
