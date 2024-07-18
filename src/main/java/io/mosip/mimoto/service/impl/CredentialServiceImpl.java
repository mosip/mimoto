package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.Format;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.LDPVc;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.LoggerUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import org.apache.commons.lang.StringUtils;
import org.apache.http.auth.InvalidCredentialsException;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_CREDENTIAL_TYPE_EXCEPTION;

@Service
public class CredentialServiceImpl implements CredentialService {

    private final Logger logger = LoggerUtil.getLogger(CredentialServiceImpl.class);

    @Autowired
    private Utilities utilities;

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    IssuersService issuerService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    IdpService idpService;

    @Value("${mosip.inji.web.authorize.url}")
    String injiWebAuthorizeUrl;

    @Override
    public TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException {
        RestTemplate restTemplate = new RestTemplate();
        IssuerDTO issuerDTO = issuerService.getIssuerConfig(issuerId);
        HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO);
        TokenResponseDTO response = restTemplate.postForObject(idpService.getTokenEndpoint(issuerDTO), request, TokenResponseDTO.class);
        if(response == null) {
            throw new IdpException("Exception occurred while performing the authorization");
        }
        return response;
    }

    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response) throws Exception {
        IssuerDTO issuerConfig = issuerService.getIssuerConfig(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getCredentialIssuerWellknown(issuerId, credentialType);
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupported(credentialIssuerWellKnownResponse, credentialType);
        VCCredentialRequest vcCredentialRequest = generateVCCredentialRequest(issuerConfig, credentialsSupportedResponse, response.getAccess_token());
        VCCredentialResponse vcCredentialResponse = downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        String dataShareUrl = dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse));
        return generatePdfForVerifiableCredentials(vcCredentialResponse, issuerConfig, credentialsSupportedResponse, dataShareUrl);
    }

    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws ApiNotAccessibleException, IOException, InvalidCredentialsException {
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        logger.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null) throw new RuntimeException("VC Credential Issue API not accessible");
        return vcCredentialResponse;
    }

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(issuerDTO.getCredential_audience(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().get(0))
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public ByteArrayInputStream generatePdfForVerifiableCredentials(VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl) throws Exception {
        LinkedHashMap<String, Object> displayProperties = loadDisplayPropertiesFromWellknown(vcCredentialResponse, credentialsSupportedResponse);
        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,  vcCredentialResponse, issuerDTO, dataShareUrl);
        return renderVCInCredentialTemplate(data);
    }

    @NotNull
    private static LinkedHashMap<String, Object> loadDisplayPropertiesFromWellknown(VCCredentialResponse vcCredentialResponse, CredentialsSupportedResponse credentialsSupportedResponse) {
        LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();

        LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();
        credentialSubject.keySet().forEach(VCProperty -> vcPropertiesFromWellKnown.put(VCProperty, credentialSubject.get(VCProperty).getDisplay().get(0).getName()));

        Set<String> orderProperty = credentialsSupportedResponse.getOrder();

        Set<String> fieldProperties = orderProperty == null ? vcPropertiesFromWellKnown.keySet() : orderProperty;
        fieldProperties.forEach(vcProperty -> {
            if(credentialProperties.get(vcProperty) != null) {
                displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty));
            }
        });
        return displayProperties;
    }


    private Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse  vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl) throws IOException, WriterException {
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

        String qrCodeImage = !"false".equals(issuerDTO.getOvp_qr_enabled()) ?
                constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl) :
                constructQRCodeWithVCData(credentialsSupportedResponse, vcCredentialResponse) ;
        data.put("qrCodeImage", qrCodeImage);
        data.put("logoUrl", issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
        data.put("rowProperties", rowProperties);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);
        return data;
    }

    @NotNull
    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data) throws IOException {
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

    private String constructQRCode(String qrData) throws WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, 650, 650);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
        return encodeToString(qrImage, "png");
    }

    private String constructQRCodeWithVCData(CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse vcCredentialResponse) throws JsonProcessingException, WriterException {
        if(!credentialsSupportedResponse.getId().equals("MOSIPVerifiableCredential")) {
            PixelPass pixelPass = new PixelPass();
            ObjectMapper objectMapper = new ObjectMapper();
            String qrData = pixelPass.generateQRData(objectMapper.writeValueAsString(vcCredentialResponse.getCredential()), "");
            return constructQRCode(qrData);
        }
        return "";
    }
    private String constructQRCodeWithAuthorizeRequest(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws WriterException, JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = constructPresentationDefinition(vcCredentialResponse);
        ObjectMapper objectMapper = new ObjectMapper();
        String presentationString = objectMapper.writeValueAsString(presentationDefinitionDTO);
        String qrData = String.format(injiWebAuthorizeUrl, URLEncoder.encode(dataShareUrl, StandardCharsets.UTF_8), URLEncoder.encode(presentationString, StandardCharsets.UTF_8));
        return constructQRCode(qrData);
    }

    private PresentationDefinitionDTO constructPresentationDefinition(VCCredentialResponse vcCredentialResponse){
        PresentationDefinitionDTO presentationDefinitionDTO = new PresentationDefinitionDTO();
        InputDescriptorDTO inputDescriptorDTO = new InputDescriptorDTO();
        Format format = new Format();
        LDPVc ldpVc = new LDPVc();

        ldpVc.setProofTypes(Collections.singletonList(vcCredentialResponse.getCredential().getProof().getType()));
        format.setLdpVc(ldpVc);
        inputDescriptorDTO.setId(UUID.randomUUID().toString());
        inputDescriptorDTO.setFormat(format);

        presentationDefinitionDTO.setId(UUID.randomUUID().toString());
        presentationDefinitionDTO.setInputDescriptors(Collections.singletonList(inputDescriptorDTO));

        return presentationDefinitionDTO;
    }



    public static String encodeToString(BufferedImage image, String type) {
        String imageString = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            ImageIO.write(image, type, bos);
            byte[] imageBytes = bos.toByteArray();
            Base64.Encoder encoder = Base64.getEncoder();
            imageString = encoder.encodeToString(imageBytes);
            bos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return imageString;
    }

    @Override
    public IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse credentialTypesWithAuthorizationEndpoint = new IssuerSupportedCredentialsResponse();

        IssuersDTO issuersDto = issuerService.getAllIssuersWithAllFields();

        Optional<IssuerDTO> issuerConfigResp = issuersDto.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()) {
            IssuerDTO issuerDto = issuerConfigResp.get();

            CredentialIssuerWellKnownResponse response = restApiClient.getApi(issuerDto.getWellKnownEndpoint(), CredentialIssuerWellKnownResponse.class);
            if (response == null) {
                throw new ApiNotAccessibleException();
            }
            List<CredentialsSupportedResponse> issuerCredentialsSupported = response.getCredentialsSupported();
            credentialTypesWithAuthorizationEndpoint.setAuthorizationEndPoint(issuerDto.getAuthorization_endpoint());
            credentialTypesWithAuthorizationEndpoint.setSupportedCredentials(issuerCredentialsSupported);

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
    public CredentialIssuerWellKnownResponse getCredentialIssuerWellknown(String issuerId, String search) throws ApiNotAccessibleException, IOException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        IssuersDTO issuersDto = issuerService.getAllIssuersWithAllFields();
        Optional<IssuerDTO> issuerConfigResp = issuersDto.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()) {
            IssuerDTO issuerDto = issuerConfigResp.get();
            credentialIssuerWellKnownResponse = restApiClient.getApi(issuerDto.getWellKnownEndpoint(), CredentialIssuerWellKnownResponse.class);
            if (credentialIssuerWellKnownResponse == null) {
                throw new ApiNotAccessibleException();
            }
        }
        return credentialIssuerWellKnownResponse;
    }

    public CredentialsSupportedResponse getCredentialSupported(CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, String credentialType) throws ApiNotAccessibleException, IOException, InvalidCredentialsException {
        Optional<CredentialsSupportedResponse> credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialsSupported().stream()
                .filter(credentialsSupported -> credentialsSupported.getId().equals(credentialType))
                .findFirst();
        if (credentialsSupportedResponse.isEmpty()){
            logger.error("Invalid credential Type passed - {}", credentialType);
            throw new InvalidCredentialsException(INVALID_CREDENTIAL_TYPE_EXCEPTION.getMessage());
        }
        return credentialsSupportedResponse.get();
    }


}
