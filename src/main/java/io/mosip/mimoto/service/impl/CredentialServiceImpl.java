package io.mosip.mimoto.service.impl;

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
import org.springframework.beans.factory.annotation.Autowired;
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
    IdpService idpService;

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
        CredentialIssuerWellKnownResponseDraft11 credentialIssuerWellKnownResponseDraft11 = getCredentialIssuerWellknown(issuerId, credentialType);
        CredentialsSupportedResponseDraft11 credentialsSupportedResponseDraft11 = getCredentialSupported(credentialIssuerWellKnownResponseDraft11, credentialType);
        VCCredentialRequest vcCredentialRequest = generateVCCredentialRequest(issuerConfig, credentialsSupportedResponseDraft11, response.getAccess_token());
        VCCredentialResponse vcCredentialResponse = downloadCredential(credentialIssuerWellKnownResponseDraft11.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        return generatePdfForVerifiableCredentials(vcCredentialResponse, issuerConfig, credentialsSupportedResponseDraft11, credentialIssuerWellKnownResponseDraft11.getCredentialEndPoint());
    }

    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws ApiNotAccessibleException, IOException, InvalidCredentialsException {
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        logger.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null) throw new RuntimeException("VC Credential Issue API not accessible");
        return vcCredentialResponse;
    }

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialsSupportedResponseDraft11 credentialsSupportedResponseDraft11, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(issuerDTO.getCredential_audience(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponseDraft11.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponseDraft11.getProofTypesSupported().get(0))
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponseDraft11.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public ByteArrayInputStream generatePdfForVerifiableCredentials(VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponseDraft11 credentialsSupportedResponseDraft11, String credentialEndPoint) throws Exception {

        LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();

        LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponseDraft11.getCredentialDefinition().getCredentialSubject();
        credentialSubject.keySet().forEach(VCProperty -> vcPropertiesFromWellKnown.put(VCProperty, credentialSubject.get(VCProperty).getDisplay().get(0).getName()));

        Set<String> orderProperty = credentialsSupportedResponseDraft11.getOrder();

        Set<String> fieldProperties = orderProperty == null ? vcPropertiesFromWellKnown.keySet() : orderProperty;
        fieldProperties.forEach(vcProperty -> {
            if(credentialProperties.get(vcProperty) != null) {
                displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty));
            }
        });
        return getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponseDraft11,  vcCredentialResponse,
                issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
    }


    private ByteArrayInputStream getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, CredentialsSupportedResponseDraft11 credentialsSupportedResponseDraft11, VCCredentialResponse  vcCredentialResponse, String issuerLogoUrl) throws IOException, WriterException {
        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();
        String backgroundColor = credentialsSupportedResponseDraft11.getDisplay().get(0).getBackgroundColor();
        String textColor = credentialsSupportedResponseDraft11.getDisplay().get(0).getTextColor();
        String credentialSupportedType = credentialsSupportedResponseDraft11.getDisplay().get(0).getName();
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

        if(!credentialsSupportedResponseDraft11.getId().equals("MOSIPVerifiableCredential")) {
            PixelPass pixelPass = new PixelPass();
            ObjectMapper objectMapper = new ObjectMapper();
            logger.info("Credential That is converted to PDF" + objectMapper.writeValueAsString(vcCredentialResponse.getCredential()));
            String qrData = pixelPass.generateQRData(objectMapper.writeValueAsString(vcCredentialResponse.getCredential()), "");
            logger.info("QR Data => " + qrData);
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, 650, 650);
            BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
            String base64Image = encodeToString(qrImage, "png");
            data.put("qrCodeImage", base64Image);
        }


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

            CredentialIssuerWellKnownResponseDraft11 response = restApiClient.getApi(issuerDto.getWellKnownEndpoint(), CredentialIssuerWellKnownResponseDraft11.class);
            if (response == null) {
                throw new ApiNotAccessibleException();
            }
            List<CredentialsSupportedResponseDraft11> issuerCredentialsSupported = response.getCredentialsSupported();
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
    public CredentialIssuerWellKnownResponseDraft11 getCredentialIssuerWellknown(String issuerId, String search) throws ApiNotAccessibleException, IOException {
        CredentialIssuerWellKnownResponseDraft11 credentialIssuerWellKnownResponseDraft11 = new CredentialIssuerWellKnownResponseDraft11();
        IssuersDTO issuersDto = issuerService.getAllIssuersWithAllFields();
        Optional<IssuerDTO> issuerConfigResp = issuersDto.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent()) {
            IssuerDTO issuerDto = issuerConfigResp.get();
            credentialIssuerWellKnownResponseDraft11 = restApiClient.getApi(issuerDto.getWellKnownEndpoint(), CredentialIssuerWellKnownResponseDraft11.class);
            if (credentialIssuerWellKnownResponseDraft11 == null) {
                throw new ApiNotAccessibleException();
            }
        }
        return credentialIssuerWellKnownResponseDraft11;
    }

    public CredentialsSupportedResponseDraft11 getCredentialSupported(CredentialIssuerWellKnownResponseDraft11 credentialIssuerWellKnownResponseDraft11, String credentialType) throws ApiNotAccessibleException, IOException, InvalidCredentialsException {
        Optional<CredentialsSupportedResponseDraft11> credentialsSupportedResponse = credentialIssuerWellKnownResponseDraft11.getCredentialsSupported().stream()
                .filter(credentialsSupported -> credentialsSupported.getId().equals(credentialType))
                .findFirst();
        if (credentialsSupportedResponse.isEmpty()){
            logger.error("Invalid credential Type passed - {}", credentialType);
            throw new InvalidCredentialsException(INVALID_CREDENTIAL_TYPE_EXCEPTION.getMessage());
        }
        return credentialsSupportedResponse.get();
    }


}
