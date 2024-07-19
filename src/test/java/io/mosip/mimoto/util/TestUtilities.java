package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.mimoto.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestUtilities {
    public static CredentialsSupportedResponseDraft11 getCredentialSupportedResponseDraft11(String credentialSupportedName){
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");
        CredentialIssuerDisplayResponse credentialIssuerDisplayResponse = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponse.setName("Given Name");
        credentialIssuerDisplayResponse.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDto = new CredentialDisplayResponseDto();
        credentialDisplayResponseDto.setDisplay(Collections.singletonList(credentialIssuerDisplayResponse));
        CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setType(List.of("VerifiableCredential", credentialSupportedName));
        credentialDefinitionResponseDto.setCredentialSubject(Map.of("name", credentialDisplayResponseDto));
        CredentialsSupportedResponseDraft11 credentialsSupportedResponseDraft11 = new CredentialsSupportedResponseDraft11();
        credentialsSupportedResponseDraft11.setFormat("ldp_vc");
        credentialsSupportedResponseDraft11.setId(credentialSupportedName+"id");
        credentialsSupportedResponseDraft11.setScope(credentialSupportedName+"_vc_ldp");
        credentialsSupportedResponseDraft11.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        credentialsSupportedResponseDraft11.setProofTypesSupported(Collections.singletonList("jwt"));
        credentialsSupportedResponseDraft11.setCredentialDefinition(credentialDefinitionResponseDto);
        return credentialsSupportedResponseDraft11;
    }

    public static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName){
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");
        CredentialIssuerDisplayResponse credentialIssuerDisplayResponse = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponse.setName("Given Name");
        credentialIssuerDisplayResponse.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDto = new CredentialDisplayResponseDto();
        credentialDisplayResponseDto.setDisplay(Collections.singletonList(credentialIssuerDisplayResponse));
        CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setType(List.of("VerifiableCredential", credentialSupportedName));
        credentialDefinitionResponseDto.setCredentialSubject(Map.of("name", credentialDisplayResponseDto));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat("ldp_vc");
        credentialsSupportedResponse.setScope(credentialSupportedName+"_vc_ldp");
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        credentialsSupportedResponse.setProofTypesSupported(new HashMap<>());
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinitionResponseDto);
        return credentialsSupportedResponse;
    }

    public static CredentialIssuerWellKnownResponseDraft11 getCredentialIssuerWellKnownResponseDtoDraft11(String issuerName, List<CredentialsSupportedResponseDraft11> credentialsSupportedResponseDraft11sDraft11s){
        CredentialIssuerWellKnownResponseDraft11 credentialIssuerWellKnownResponseDraft11 = new CredentialIssuerWellKnownResponseDraft11();
        credentialIssuerWellKnownResponseDraft11.setCredentialIssuer(issuerName);
        credentialIssuerWellKnownResponseDraft11.setCredentialEndPoint("/credential_endpoint");
        credentialIssuerWellKnownResponseDraft11.setCredentialsSupported(credentialsSupportedResponseDraft11sDraft11s);
        return credentialIssuerWellKnownResponseDraft11;
    }



    public static CredentialIssuerWellKnownResponse getCredentialIssuerWellKnownResponseDto(String issuerName, Map<String,CredentialsSupportedResponse> credentialsSupportedResponses){
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        credentialIssuerWellKnownResponse.setCredentialIssuer(issuerName);
        credentialIssuerWellKnownResponse.setCredentialEndPoint("/credential_endpoint");
        credentialIssuerWellKnownResponse.setCredentialConfigurationsSupported(credentialsSupportedResponses);
        return credentialIssuerWellKnownResponse;
    }
    public static IssuerDTO getIssuerDTO(String issuerName) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        DisplayDTO display = new DisplayDTO();
        display.setName(issuerName);
        display.setTitle("Download via " + issuerName);
        display.setDescription(issuerName + " description");
        display.setLanguage("en");
        display.setLogo(logo);
        IssuerDTO issuer = new IssuerDTO();
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        if (issuerName.equals("Issuer1")) issuer.setWellKnownEndpoint("/.well-known");
        else {
            issuer.setRedirect_uri(null);
            issuer.setAuthorization_endpoint(null);
            issuer.setCredential_endpoint(null);
            issuer.setToken_endpoint(null);
            issuer.setScopes_supported(null);
        }
        return issuer;
    }

    public static String getExpectedWellKnownJson() {
        return "{"
                + "\"credential_issuer\": \"Issuer1\","
                + "\"credential_endpoint\": \"/credential_endpoint\","
                + "\"credential_configurations_supported\": {"
                + "\"CredentialType1\": {"
                + "\"format\": \"ldp_vc\","
                + "\"scope\": \"CredentialType1_vc_ldp\","
                + "\"display\": [{"
                + "\"logo\": {"
                + "\"url\": \"/logo\","
                + "\"alt_text\": \"logo-url\""
                + "},"
                + "\"name\": \"CredentialType1\","
                + "\"locale\": \"en\","
                + "\"text_color\": \"#FFFFFF\","
                + "\"background_color\": \"#B34622\""
                + "}],"
                + "\"proof_types_supported\": {},"
                + "\"credential_definition\": {"
                + "\"type\": [\"VerifiableCredential\", \"CredentialType1\"],"
                + "\"credentialSubject\": {"
                + "\"name\": {"
                + "\"display\": [{"
                + "\"name\": \"Given Name\","
                + "\"locale\": \"en\""
                + "}]"
                + "}"
                + "}"
                + "}"
                + "}"
                + "}"
                + "}";
    }

    public static IssuerDTO getIssuerConfigDTO(String issuerName, List<String> nullFields) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        DisplayDTO display = new DisplayDTO();
        display.setName(issuerName);
        display.setTitle("Download via " + issuerName);
        display.setDescription(issuerName + " description");
        display.setLanguage("en");
        display.setLogo(logo);
        IssuerDTO issuer = new IssuerDTO();
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        issuer.setEnabled("true");
        if (issuerName.equals("Issuer1")) issuer.setWellKnownEndpoint("/.well-known");
        else {
            if (!nullFields.contains("redirect_uri"))
                issuer.setRedirect_uri("/redirection");
            if (!nullFields.contains("authorization_audience"))
                issuer.setAuthorization_audience("/authorization_audience");
            if (!nullFields.contains("redirect_uri"))
                issuer.setRedirect_uri("/redirection");
            if (!nullFields.contains("authorization_endpoint"))
                issuer.setAuthorization_endpoint("/authorization_endpoint");
            if (!nullFields.contains("token_endpoint"))
                issuer.setToken_endpoint("/token_endpoint");
            if (!nullFields.contains("proxy_token_endpoint"))
                issuer.setProxy_token_endpoint("/proxy_token_endpoint");
            if (!nullFields.contains("credential_endpoint"))
                issuer.setCredential_endpoint("/credential_endpoint");
            if (!nullFields.contains("credential_audience"))
                issuer.setCredential_audience("/credential_audience");
            if (!nullFields.contains("additional_headers"))
                issuer.setAdditional_headers(Map.of("Content-Type", "application/json"));
        }
        return issuer;
    }
}
