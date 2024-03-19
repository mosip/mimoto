package io.mosip.mimoto.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.v2.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.LoggerUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.xhtmlrenderer.pdf.ITextRenderer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class IssuersServiceImpl implements IssuersService {
    private final Logger logger = LoggerUtil.getLogger(IssuersServiceImpl.class);

    @Autowired
    private Utilities utilities;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private JoseUtil joseUtil;

    @Value("${mosip.oidc.p12.filename}")
    private String fileName;

    @Value("${mosip.oidc.p12.password}")
    private String cyptoPassword;

    @Value("${mosip.oidc.p12.path}")
    String keyStorePath;

    @Override
    public IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuers;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        Gson gsonWithIssuerDataOnlyFilter = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        issuers = gsonWithIssuerDataOnlyFilter.fromJson(issuersConfigJsonValue, IssuersDTO.class);

        // Filter issuers list with search string
        if (!StringUtils.isEmpty(search)) {
            List<IssuerDTO> filteredIssuers = issuers.getIssuers().stream()
                    .filter(issuer -> issuer.getDisplay().stream()
                            .anyMatch(displayDTO -> displayDTO.getName().toLowerCase().contains(search.toLowerCase())))
                    .collect(Collectors.toList());
            issuers.setIssuers(filteredIssuers);
            return issuers;
        }
        return issuers;
    }

    @Override
    public IssuersDTO getAllIssuersWithAllFields() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuers;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        Gson gsonWithIssuerDataOnlyFilter = new GsonBuilder().create();
        issuers = gsonWithIssuerDataOnlyFilter.fromJson(issuersConfigJsonValue, IssuersDTO.class);

        return issuers;
    }



    @Override
    public IssuerDTO getIssuerConfig(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = null;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        IssuersDTO issuers = new Gson().fromJson(issuersConfigJsonValue, IssuersDTO.class);
        Optional<IssuerDTO> issuerConfigResp = issuers.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent())
            issuerDTO = issuerConfigResp.get();
        return issuerDTO;
    }

    @Override
    public IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse supportedCredentialsWithAuthorizationEndPoint = new IssuerSupportedCredentialsResponse();

        IssuersDTO issuersDto = getAllIssuersWithAllFields();
        Optional<IssuerDTO> issuerConfigResp = issuersDto.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()) {
            IssuerDTO issuerDto = issuerConfigResp.get();

            // Get credential supported types from well known endpoint
            CredentialIssuerWellKnownResponse response = restApiClient.getApi(issuerDto.getCredential_issuer(), CredentialIssuerWellKnownResponse.class);
            if (response == null) {
                response = getCredentialWellKnownFromJson();
            }
            List<CredentialsSupportedResponse> issuerCredentialsSupported = response.getCredentials_supported();
            supportedCredentialsWithAuthorizationEndPoint.setAuthorization_endpoint(issuerDto.getAuthorization_endpoint());
            supportedCredentialsWithAuthorizationEndPoint.setSupportedCredentials(issuerCredentialsSupported);

            // Filter Credential supported types with search string
            if (!StringUtils.isEmpty(search)){
                supportedCredentialsWithAuthorizationEndPoint.setSupportedCredentials(issuerCredentialsSupported
                        .stream()
                        .filter(credentialsSupportedResponse -> credentialsSupportedResponse.getDisplay().stream()
                                .anyMatch(credDisplay -> credDisplay.getName().toLowerCase().contains(search.toLowerCase())))
                        .collect(Collectors.toList()));
            }
            return supportedCredentialsWithAuthorizationEndPoint;
        }
        return supportedCredentialsWithAuthorizationEndPoint;
    }

    private CredentialIssuerWellKnownResponse getCredentialWellKnownFromJson() throws IOException, ApiNotAccessibleException {
        String v2CredentialsSupportedResponseJson = utilities.getV2CredentialsSupportedConfigJsonValue();
        if (v2CredentialsSupportedResponseJson == null){
            throw new ApiNotAccessibleException();
        }
        return new Gson().fromJson(v2CredentialsSupportedResponseJson, CredentialIssuerWellKnownResponse.class);
    }

    @Override
    public ByteArrayInputStream generatePdfForVerifiableCredentials(String accessToken, String issuerId, String credentialsSupportedId) throws Exception {
        IssuersDTO allIssuers = getAllIssuersWithAllFields();
        Optional<IssuerDTO> issuerConfigResp = allIssuers.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()){
            CredentialIssuerWellKnownResponse credentialIssuerResponse = restApiClient.getApi(issuerConfigResp.get().getWellKnownEndpoint(), CredentialIssuerWellKnownResponse.class); //TODO: check which url to pass
            if (credentialIssuerResponse == null) {
                credentialIssuerResponse = getCredentialWellKnownFromJson();
            }
            Optional<CredentialsSupportedResponse> credentialsSupportedResponse = credentialIssuerResponse.getCredentials_supported().stream()
                    .filter(credentialsSupported -> credentialsSupported.getId().equals(credentialsSupportedId))
                    .findFirst();
            if (credentialsSupportedResponse.isPresent()) {
                LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
                Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.get().getCredential_definition().getCredentialSubject();
                credentialSubject.keySet().forEach(VCProperty -> vcPropertiesFromWellKnown.put(VCProperty, credentialSubject.get(VCProperty).getDisplay().get(0).getName()));
                String backgroundColor = credentialsSupportedResponse.get().getDisplay().get(0).getBackground_color();
                String textColor = credentialsSupportedResponse.get().getDisplay().get(0).getText_color();
                VCCredentialRequest vcCredentialRequest = generateVCCredentialRequest(issuerConfigResp.get(), credentialsSupportedResponse.get(), accessToken);
                logger.info("VC Credential Request is -> " + vcCredentialRequest);
                VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialIssuerResponse.getCredential_endpoint(), MediaType.APPLICATION_JSON,
                        vcCredentialRequest, VCCredentialResponse.class, accessToken);
                logger.info("VC Credential Response is -> " + vcCredentialResponse);
                Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();
                LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
                vcPropertiesFromWellKnown.keySet().forEach(vcProperty -> displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty)));
                return getPdfResourceFromVcProperties(displayProperties, textColor, backgroundColor,
                        credentialsSupportedResponse.get().getDisplay().get(0).getName(),
                        issuerConfigResp.get().getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
            }
        }
        throw new RuntimeException("Invalid Credential Supported id passed");
    }

    private VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws ParseException {
        //Getting public key from the p12 file
        PublicKey publicKeyString = joseUtil.getPublicKeyString(keyStorePath, fileName, issuerDTO.getClient_alias(), cyptoPassword);
        //Generating access from the public key with custom header
        String jwt = joseUtil.generateJwt(publicKeyString, keyStorePath, fileName, issuerDTO.getClient_alias(),
                cyptoPassword, issuerDTO.getCredential_audience(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proof_type(credentialsSupportedResponse.getProof_types_supported().get(0))
                        .jwt(jwt)
                        .build())
                .credential_definition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredential_definition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    private ByteArrayInputStream getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, String textColor,
                                                                String backgroundColor,
                                                                String credentialSupportedType, String issuerLogoUrl) throws IOException {
        Map<String, Object> data = new HashMap<>();
        Context context = new Context();
        LinkedHashMap<String, Object> headerProperties = new LinkedHashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();

        //Assigning two properties at the top of pdf and the rest dynamically below them
        displayProperties.entrySet().stream()
                .forEachOrdered(entry -> {
                    if (headerProperties.size() < 2) {
                        headerProperties.put(entry.getKey(), entry.getValue());
                    } else {
                        rowProperties.put(entry.getKey(), entry.getValue());
                    }
                });

        int rowPropertiesCount =  rowProperties.size();
        data.put("logoUrl", issuerLogoUrl);
        data.put("headerProperties", headerProperties);
        data.put("rowProperties", rowProperties);
        data.put("keyFontColor", textColor);
        data.put("bgColor", backgroundColor);
        data.put("rowPropertiesMargin", rowPropertiesCount % 2 == 0 ? (rowPropertiesCount/2 -1)*50 : (rowPropertiesCount/2)*50); //for adjusting the height in pdf for dynamic properties
        data.put("titleName", credentialSupportedType);

        context.setVariables(data);
        String  credentialTemplate = utilities.getCredentialSupportedTemplateString();

        Properties props = new Properties();
        props.setProperty("resource.loader", "class");
        props.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        Velocity.init(props);
        VelocityContext velocityContext = new VelocityContext(data);

        // Merge the context with the template
        StringWriter writer = new StringWriter();
        Velocity.evaluate(velocityContext, writer, "Credential Template", credentialTemplate);

        // Get the merged HTML string
        String mergedHtml = writer.toString();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ITextRenderer renderer = new ITextRenderer();
        renderer.setDocumentFromString(mergedHtml);
        renderer.layout();
        renderer.createPDF(outputStream);
        return new ByteArrayInputStream(outputStream.toByteArray());
    }
}
