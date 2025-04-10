package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseDTO;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.dto.openid.presentation.*;
import org.springframework.util.ResourceUtils;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.itextpdf.kernel.pdf.canvas.parser.PdfTextExtractor;

public class TestUtilities {

    public static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName) {
        return getCredentialSupportedResponse(credentialSupportedName, true);
    }

    public static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName, boolean includeBackgroundImage) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("https://logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        if (includeBackgroundImage) {
            credentialSupportedDisplay.setBackgroundImage(new BackgroundImageDTO("https://bgimage"));
        }
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");

        CredentialIssuerDisplayResponse credentialIssuerDisplayResponseForName = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponseForName.setName("Given Name");
        credentialIssuerDisplayResponseForName.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDtoForName = new CredentialDisplayResponseDto();
        credentialDisplayResponseDtoForName.setDisplay(List.of(credentialIssuerDisplayResponseForName));

        CredentialIssuerDisplayResponse credentialIssuerDisplayResponseForEmail = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponseForEmail.setName("Given Email");
        credentialIssuerDisplayResponseForEmail.setLocale("pt");
        CredentialDisplayResponseDto credentialDisplayResponseDtoForEmail = new CredentialDisplayResponseDto();
        credentialDisplayResponseDtoForEmail.setDisplay(List.of(credentialIssuerDisplayResponseForEmail));

        CredentialIssuerDisplayResponse credentialIssuerDisplayResponseForUIN = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponseForUIN.setName("UIN");
        credentialIssuerDisplayResponseForUIN.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDtoForUIN = new CredentialDisplayResponseDto();
        credentialDisplayResponseDtoForUIN.setDisplay(List.of(credentialIssuerDisplayResponseForUIN));

        CredentialIssuerDisplayResponse credentialIssuerDisplayResponseForDOB = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponseForDOB.setName("dob");
        credentialIssuerDisplayResponseForDOB.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDtoForDOB = new CredentialDisplayResponseDto();
        credentialDisplayResponseDtoForDOB.setDisplay(List.of(credentialIssuerDisplayResponseForDOB));


        CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setType(List.of("VerifiableCredential", credentialSupportedName));
        credentialDefinitionResponseDto.setCredentialSubject(new LinkedHashMap<>() {{
            put("name", createCredentialDisplayResponse("Given Name", "en"));
            put("email", createCredentialDisplayResponse("Given Email", "pt"));
            put("uin", createCredentialDisplayResponse("UIN", "en"));
            put("dob", createCredentialDisplayResponse("dob", "en"));
        }});
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat("ldp_vc");
        credentialsSupportedResponse.setScope(credentialSupportedName + "_vc_ldp");
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        HashMap<String, ProofTypesSupported> proofTypesSupportedHashMap = new HashMap<>();
        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(List.of("RS256"));
        proofTypesSupportedHashMap.put("jwt", proofTypesSupported);
        credentialsSupportedResponse.setProofTypesSupported(proofTypesSupportedHashMap);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinitionResponseDto);
        return credentialsSupportedResponse;
    }

    private static CredentialDisplayResponseDto createCredentialDisplayResponse(String name, String locale) {
        CredentialIssuerDisplayResponse issuerDisplayResponse = new CredentialIssuerDisplayResponse();
        issuerDisplayResponse.setName(name);
        issuerDisplayResponse.setLocale(locale);

        CredentialDisplayResponseDto displayResponseDto = new CredentialDisplayResponseDto();
        displayResponseDto.setDisplay(List.of(issuerDisplayResponse));

        return displayResponseDto;
    }

    public static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName, String format) {
        return getCredentialSupportedResponse(credentialSupportedName, format, true);
    }

    public static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName, String format, boolean includeBackgroundImage) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("https://logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");
        if (includeBackgroundImage) {
            credentialSupportedDisplay.setBackgroundImage(new BackgroundImageDTO("https://bgimage"));
        }
        CredentialIssuerDisplayResponse credentialIssuerDisplayResponse = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponse.setName("Given Name");
        credentialIssuerDisplayResponse.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDto = new CredentialDisplayResponseDto();
        credentialDisplayResponseDto.setDisplay(Collections.singletonList(credentialIssuerDisplayResponse));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat(format);
        credentialsSupportedResponse.setScope(credentialSupportedName + "_vc_" + format);
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        HashMap<String, ProofTypesSupported> proofTypesSupportedHashMap = new HashMap<>();
        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(List.of("RS256"));
        proofTypesSupportedHashMap.put("jwt", proofTypesSupported);
        credentialsSupportedResponse.setProofTypesSupported(proofTypesSupportedHashMap);
        credentialsSupportedResponse.setDoctype("org.iso.18018");
        credentialsSupportedResponse.setClaims(Map.of("org.iso.18018", Map.of("given_name", Map.of("display", List.of(Map.of("name", "Given Name", "locale", "en"))))));
        return credentialsSupportedResponse;
    }

    public static CredentialIssuerWellKnownResponse getCredentialIssuerWellKnownResponseDto(String issuerName, Map<String, CredentialsSupportedResponse> credentialsSupportedResponses) {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                "https://dev/" + issuerName,
                List.of("https://auth-server.env.net"),
                "https://dev/issuance/credential",
                credentialsSupportedResponses);
        return credentialIssuerWellKnownResponse;
    }

    public static CredentialIssuerConfiguration getCredentialIssuerConfigurationResponseDto(String issuerName, String credentialType, List<String> nullFields) {
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(nullFields);
        Map<String, CredentialsSupportedResponse> credentialsSupportedResponses = Map.of(credentialType, getCredentialSupportedResponse(credentialType));
        CredentialIssuerConfiguration credentialIssuerConfiguration = new CredentialIssuerConfiguration("https://dev/" + issuerName, List.of("https://auth-server.env.net"), "https://dev/issuance/credential", credentialsSupportedResponses, authorizationServerWellKnownResponse);
        return credentialIssuerConfiguration;
    }

    public static AuthorizationServerWellKnownResponse getAuthServerWellknownResponseDto(List<String> nullFields) {
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = new AuthorizationServerWellKnownResponse();
        if (!nullFields.contains("authorization_endpoint")) {
            authorizationServerWellKnownResponse.setAuthorizationEndpoint("https://dev/authorize");
        }
        if (!nullFields.contains("token_endpoint")) {
            authorizationServerWellKnownResponse.setTokenEndpoint("https://dev/token");
        }
        if (!nullFields.contains("grant_types_supported")) {
            authorizationServerWellKnownResponse.setGrantTypesSupported(List.of("authorization_code"));
        }
        return authorizationServerWellKnownResponse;
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
        issuer.setIssuer_id(issuerName + "id");
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setCredential_issuer_host("https://issuer.env.net");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        issuer.setWellknown_endpoint("/well-known-proxy");
        issuer.setProxy_token_endpoint("/well-known-proxy");
        if (!(issuerName.equals("Issuer2") || issuerName.equals("Issuer4"))) { //use it for testing /issuers or /issuers?search=issuer2 endpoints
            issuer.setAuthorization_audience("/well-known-proxy");
        }
        return issuer;
    }

    public static IssuerDTO getIssuerConfigDTO(String issuerName) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("https://logo");
        logo.setAlt_text("logo-url");
        DisplayDTO display = new DisplayDTO();
        display.setName(issuerName);
        display.setTitle("Download via " + issuerName);
        display.setDescription(issuerName + " description");
        display.setLanguage("en");
        display.setLogo(logo);
        IssuerDTO issuer = new IssuerDTO();
        issuer.setIssuer_id(issuerName + "id");
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        issuer.setClient_alias("test-client-alias");
        issuer.setRedirect_uri("https://oauthredirect");
        issuer.setEnabled("true");
        issuer.setProtocol("OpenId4VCI");
        issuer.setWellknown_endpoint("https://issuer.env.net/.well-known/openid-credential-issuer");
        issuer.setCredential_issuer_host("https://issuer.env.net");
        issuer.setToken_endpoint("https://dev/"+issuerName + "id");
        issuer.setAuthorization_audience("https://dev/auth-server/token");
        issuer.setProxy_token_endpoint("https://dev/auth-server/token");
        return issuer;
    }

    public static IssuerDTO getIssuerConfigDTOWithInvalidFieldValues(String issuerName, boolean emptyValues, boolean invalidUrls) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl(emptyValues ? "/logo" : "https://logo");
        logo.setAlt_text("logo-url");

        DisplayDTO display = new DisplayDTO();
        display.setName(emptyValues ? "" : issuerName);
        display.setTitle(emptyValues ? "" : "Download via " + issuerName);
        display.setDescription(emptyValues ? "" : issuerName + " description");
        display.setLanguage(emptyValues ? "" : "en");
        display.setLogo(logo);

        IssuerDTO issuer = new IssuerDTO();
        issuer.setIssuer_id(emptyValues ? "" : issuerName + "id");
        issuer.setCredential_issuer(emptyValues ? "" : issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id(emptyValues ? "" : "123");
        issuer.setClient_alias(emptyValues ? "" : "test-client-alias");
        issuer.setRedirect_uri(emptyValues ? "" : "https://oauthredirect");
        issuer.setEnabled(emptyValues ? "" : "true");
        issuer.setProtocol(emptyValues ? "" : "OpenId4VCI");

        // Handle valid and invalid URLs
        issuer.setWellknown_endpoint(emptyValues ? "" : (invalidUrls ? "ht//issuer.env.net/.well-known/openid-credential-issuer" : "https://issuer.env.net/.well-known/openid-credential-issuer"));
        issuer.setCredential_issuer_host(emptyValues ? "" : (invalidUrls ? "https//issuer.env.net" : "https://issuer.env.net"));
        issuer.setToken_endpoint(emptyValues ? "" : (invalidUrls ? "h://dev/token" : "https://dev/token"));
        issuer.setAuthorization_audience(emptyValues ? "" : (invalidUrls ? "htt://dev/auth-server/token" : "https://dev/auth-server/token"));
        issuer.setProxy_token_endpoint(emptyValues ? "" : (invalidUrls ? "htp://dev/auth-server/token" : "https://dev/auth-server/token"));

        return issuer;
    }

    public static String getExpectedWellKnownJson() throws IOException {
        return getExpectedWellKnownJson(true);
    }

    public static String getExpectedWellKnownJson(boolean includeBackgroundImage) throws IOException {
        String fileName = includeBackgroundImage ? "expectedWellknown.json" : "expectedWellknownWithoutBackground.json";
        return new String(Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "responses/" + fileName).toPath())).trim();
    }

    public static String getExpectedIssuersConfigJson() throws IOException {
        return new String(Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "responses/expectedIssuerConfig.json").toPath())).trim();
    }

    public static ByteArrayInputStream generatePdfFromHTML() {
        String htmlContent = "<html><body><h1>PDF</h1></body></html>";
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PdfWriter pdfwriter = new PdfWriter(outputStream);
        DefaultFontProvider defaultFont = new DefaultFontProvider(true, false, false);
        ConverterProperties converterProperties = new ConverterProperties();
        converterProperties.setFontProvider(defaultFont);
        HtmlConverter.convertToPdf(htmlContent, pdfwriter, converterProperties);

        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    public static String extractTextFromPdf(InputStream pdfStream) throws IOException {
        PdfDocument pdfDocument = new PdfDocument(new PdfReader(pdfStream));
        StringBuilder text = new StringBuilder();

        for (int i = 1; i <= pdfDocument.getNumberOfPages(); i++) {
            text.append(PdfTextExtractor.getTextFromPage(pdfDocument.getPage(i)));
        }

        pdfDocument.close();
        return text.toString().trim();
    }

    public static PresentationRequestDTO getPresentationRequestDTO() {
        return PresentationRequestDTO.builder()
                .presentationDefinition(getPresentationDefinitionDTO())
                .clientId("test_client_id")
                .resource("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test")
                .responseType("test_response_type")
                .redirectUri("test_redirect_uri").build();
    }

    public static VCCredentialProperties getVCCredentialPropertiesDTO(String type) {

        ArrayList<String> contextList = new ArrayList<>();
        contextList.add("context-1");
        contextList.add("context-2");

        List<String> typeList = new ArrayList<>();
        typeList.add("VerifiableCredential");
        typeList.add("VCTypeCredential");

        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("name", List.of(Map.of("value", "full name", "language", "en")));
        credentialSubject.put("email", "@gmail.com");
        credentialSubject.put("uin", "2144641120");
        credentialSubject.put("dob", "");

        VCCredentialResponseProof vcCredentialResponseProof = VCCredentialResponseProof.builder()
                .type(type)
                .proofPurpose("test-proofPurpose")
                .proofValue("test-proofValue")
                .jws("test-jws")
                .verificationMethod("test-verificationMethod").build();

        return VCCredentialProperties.builder()
                .id("test-id")
                .issuer("test-issuer")
                .issuanceDate("test-issuanceDate")
                .expirationDate("test-expirationDate")
                .context(contextList)
                .type(typeList)
                .proof(vcCredentialResponseProof)
                .credentialSubject(credentialSubject).build();
    }

    public static VCCredentialRequest getVCCredentialRequestDTO() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt("jwt")
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public static VCCredentialResponse getVCCredentialResponseDTO(String type) {
        return VCCredentialResponse.builder()
                .credential(getVCCredentialPropertiesDTO(type))
                .format("ldp_vc").build();
    }

    public static DataShareResponseDto getDataShareResponseDTO(String errorCode) {
        return DataShareResponseDto.builder()
                .dataShare(new DataShare())
                .errors(List.of(new ErrorDTO(errorCode == "" ? "Expired!" : errorCode, "Download is failed as credential is expired")))
                .build();
    }


    public static io.mosip.mimoto.dto.idp.TokenResponseDTO getTokenResponseDTO() {
        return io.mosip.mimoto.dto.idp.TokenResponseDTO.builder()
                .id_token("test-id-token")
                .access_token("test-accesstoken")
                .expires_in(12345)
                .scope("test-scope")
                .token_type("test-token-type")
                .build();
    }

    public static PresentationDefinitionDTO getPresentationDefinitionDTO() {
        FilterDTO filterDTO = FilterDTO.builder().type("String").pattern("test-credential").build();
        FieldDTO fieldDTO = FieldDTO.builder().path(new String[]{"$.type"}).filter(filterDTO).build();
        ConstraintsDTO constraintsDTO = ConstraintsDTO.builder().fields(new FieldDTO[]{fieldDTO}).build();
        Map<String, List<String>> proofTypes = Map.of("proofTypes", Collections.singletonList("Ed25519Signature2020"));
        Map<String, Map<String, List<String>>> format = Map.of("ldpVc", proofTypes);
        InputDescriptorDTO inputDescriptorDTO = InputDescriptorDTO.builder().id("test-input-id").format(format).constraints(constraintsDTO).build();

        return PresentationDefinitionDTO.builder()
                .inputDescriptors(Collections.singletonList(inputDescriptorDTO))
                .id("test-id").build();
    }

    public static VerifiablePresentationDTO getVerifiablePresentationDTO() {
        List<String> contextList = new ArrayList<>();
        contextList.add("https://www.w3.org/2018/credentials/v1");

        List<String> typeList = new ArrayList<>();
        typeList.add("VerifiablePresentation");

        return VerifiablePresentationDTO.builder()
                .verifiableCredential(Collections.singletonList(getVCCredentialPropertiesDTO("Ed25519Signature2020")))
                .context(contextList)
                .type(typeList).build();
    }

    public static VerifiersDTO getTrustedVerifiers() {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri")).build();

        return VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();
    }

    public static String getObjectAsString(Object object) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(object);
    }

    public static DataShareResponseWrapperDTO getDataShareResponseWrapperDTO() {
        ErrorDTO errorDTO = ErrorDTO.builder().errorCode("test-errorCode").errorMessage("test-errorMessage").build();
        DataShareResponseDTO dataShareResponseDTO = DataShareResponseDTO.builder()
                .url("https://test-url")
                .validForInMinutes(1)
                .transactionsAllowed(1)
                .policyId("static-policyid")
                .subscriberId("static-subscriberId").build();

        return DataShareResponseWrapperDTO.builder()
                .id("test-id")
                .version("test-version")
                .responsetime("test-responsetime")
                .dataShare(dataShareResponseDTO)
                .errors(Collections.singletonList(errorDTO)).build();
    }
}
