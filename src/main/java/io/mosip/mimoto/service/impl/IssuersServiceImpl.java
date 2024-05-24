package io.mosip.mimoto.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDisplayResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialDefinition;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequestProof;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.LoggerUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Collectors;

@Service
public class IssuersServiceImpl implements IssuersService {
    private final Logger logger = LoggerUtil.getLogger(IssuersServiceImpl.class);

    private static final String context = "https://www.w3.org/2018/credentials/v1";

    @Autowired
    private Utilities utilities;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private JoseUtil joseUtil;


    @Override
    public IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuers;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        Gson gsonWithIssuerDataOnlyFilter = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        issuers = gsonWithIssuerDataOnlyFilter.fromJson(issuersConfigJsonValue, IssuersDTO.class);
        List<IssuerDTO> enabledIssuers = issuers.getIssuers().stream()
                .filter(issuer -> "true".equals(issuer.getEnabled()))
                .collect(Collectors.toList());
        issuers.setIssuers(enabledIssuers);

        // Filter issuers list with search string
        if (!StringUtils.isEmpty(search)) {
            List<IssuerDTO> filteredIssuers = issuers.getIssuers().stream()
                    .filter(issuer -> issuer.getDisplay().stream()
                            .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains(search.toLowerCase())))
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
        else
            throw new InvalidIssuerIdException();
        return issuerDTO;
    }

    @Override
    public IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse credentialTypesWithAuthorizationEndpoint = new IssuerSupportedCredentialsResponse();

        IssuersDTO issuersDto = getAllIssuersWithAllFields();

        Optional<IssuerDTO> issuerConfigResp = issuersDto.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()) {
            IssuerDTO issuerDto = issuerConfigResp.get();

            // Get credential supported types from well known endpoint
            CredentialIssuerWellKnownResponse response = restApiClient.getApi(issuerDto.getWellKnownEndpoint(), CredentialIssuerWellKnownResponse.class);
            if (response == null) {
                throw new ApiNotAccessibleException();
            }
            List<CredentialsSupportedResponse> issuerCredentialsSupported = response.getCredentialsSupported();
            credentialTypesWithAuthorizationEndpoint.setAuthorizationEndPoint(issuerDto.getAuthorization_endpoint());
            credentialTypesWithAuthorizationEndpoint.setSupportedCredentials(issuerCredentialsSupported);

            // Filter Credential supported types with search string
            if (!StringUtils.isEmpty(search)){
                credentialTypesWithAuthorizationEndpoint.setSupportedCredentials(issuerCredentialsSupported
                        .stream()
                        .filter(credentialsSupportedResponse -> credentialsSupportedResponse.getDisplay().stream()
                                .anyMatch(credDisplay -> credDisplay.getName().toLowerCase().contains(search.toLowerCase())))
                        .collect(Collectors.toList()));
            }
            return credentialTypesWithAuthorizationEndpoint;
        }
        return credentialTypesWithAuthorizationEndpoint;
    }

    @Override
    public ByteArrayInputStream generatePdfForVerifiableCredentials(String accessToken, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String credentialEndPoint) throws Exception {
        LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();

        credentialSubject.keySet().forEach(VCProperty -> vcPropertiesFromWellKnown.put(VCProperty, credentialSubject.get(VCProperty).getDisplay().get(0).getName()));
        VCCredentialRequest vcCredentialRequest = generateVCCredentialRequest(issuerDTO, credentialsSupportedResponse, accessToken);
        logger.debug("VC Credential Request is -> " + vcCredentialRequest);

        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndPoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        logger.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null) throw new RuntimeException("VC Credential Issue API not accessible");
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();
        LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
        List<String> orderProperty = credentialsSupportedResponse.getOrder();
        if(orderProperty == null) {
            vcPropertiesFromWellKnown.keySet().forEach(vcProperty -> displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty)));
        } else {
            orderProperty.forEach(vcProperty -> displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty)));
        }
        return getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,  vcCredentialResponse,
                issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
    }

    private VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(issuerDTO.getCredential_audience(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().get(0))
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of(context))
                        .build())
                .build();
    }

    private ByteArrayInputStream getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse  vcCredentialResponse, String issuerLogoUrl) throws IOException {
        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();
        String backgroundColor = credentialsSupportedResponse.getDisplay().get(0).getBackgroundColor();
        String textColor = credentialsSupportedResponse.getDisplay().get(0).getTextColor();
        String credentialSupportedType = credentialsSupportedResponse.getDisplay().get(0).getName();
        String face = vcCredentialResponse.getCredential().getCredentialSubject().get("face") != null ? (String) vcCredentialResponse.getCredential().getCredentialSubject().get("face") : null;

        displayProperties.entrySet().stream()
                .forEachOrdered(entry -> {
                    if(entry.getValue() instanceof Map) {
                        rowProperties.put(entry.getKey(), ((Map<?, ?>) entry.getValue()).get("value"));
                    } else if(entry.getValue() instanceof List) {
                        String value = "";
                        if( ((List<?>) entry.getValue()).get(0) instanceof String) {
                            value = ((List<String>) entry.getValue()).stream().reduce((field1, field2) -> field1 + ", " + field2 ).get();
                        } else {
                            value = (String) ((Map<?, ?>) ((List<?>) entry.getValue()).get(0)).get("value");
                        }
                        rowProperties.put(entry.getKey(), value);
                    } else {
                        rowProperties.put(entry.getKey(), entry.getValue());
                    }
                });

        data.put("logoUrl", issuerLogoUrl);
        data.put("rowProperties", rowProperties);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);


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

        PdfWriter pdfwriter = new PdfWriter(outputStream);
        DefaultFontProvider defaultFont = new DefaultFontProvider(true, false, false);
        ConverterProperties converterProperties = new ConverterProperties();
        converterProperties.setFontProvider(defaultFont);
        HtmlConverter.convertToPdf(mergedHtml, pdfwriter, converterProperties);
        return new ByteArrayInputStream(outputStream.toByteArray());
    }
}
