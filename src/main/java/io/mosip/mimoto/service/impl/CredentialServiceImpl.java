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
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
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

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@Service
public class CredentialServiceImpl implements CredentialService {

    @Autowired
    private Utilities utilities;

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    IssuersService issuersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    IdpService idpService;

    @Autowired
    RestTemplate restTemplate;

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:2000}")
    Integer allowedQRDataSizeLimit;

    @Autowired
    PresentationServiceImpl presentationService;

    PixelPass pixelPass;
    CredentialsVerifier credentialsVerifier;

    @PostConstruct
    public void init(){
        pixelPass = new PixelPass();
        credentialsVerifier = new CredentialsVerifier();
    }

    @Override
    public TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfigurationResponse credentialIssuerConfigurationResponse = issuersService.getIssuerConfiguration(issuerId);
        String tokenEndpoint = idpService.getTokenEndpoint(credentialIssuerConfigurationResponse);
        HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO, tokenEndpoint);
        TokenResponseDTO response = restTemplate.postForObject(tokenEndpoint, request, TokenResponseDTO.class);
        if (response == null) {
            throw new IdpException("Exception occurred while performing the authorization");
        }
        return response;
    }

    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfigurationResponse issuerConfigurationResponse = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                issuerConfigurationResponse.getCredentialIssuer(),
                issuerConfigurationResponse.getAuthorizationServers(),
                issuerConfigurationResponse.getCredentialEndPoint(),
                issuerConfigurationResponse.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        VCCredentialRequest vcCredentialRequest = generateVCCredentialRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token());
        VCCredentialResponse vcCredentialResponse = downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || verifyCredential(vcCredentialResponse);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            return generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
        throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }

    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException {
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        log.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null) throw new RuntimeException("VC Credential Issue API not accessible");
        return vcCredentialResponse;
    }

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public ByteArrayInputStream generatePdfForVerifiableCredentials(String credentialType, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {
        LinkedHashMap<String, Object> displayProperties = loadDisplayPropertiesFromWellknown(vcCredentialResponse, credentialsSupportedResponse, locale);
        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,  vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity, locale);
        return renderVCInCredentialTemplate(data, issuerDTO.getIssuer_id(), credentialType);
    }

    public Boolean verifyCredential(VCCredentialResponse vcCredentialResponse) throws VCVerificationException, JsonProcessingException {
        log.info("Initiated the VC Verification : Started");
        String credentialString = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());
        VerificationResult verificationResult = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        if(!verificationResult.getVerificationStatus()){
            throw new VCVerificationException(verificationResult.getVerificationErrorCode().toLowerCase(), verificationResult.getVerificationMessage());
        }
        log.info("Completed the VC Verification : Completed -> result : " + verificationResult);
        return true;
    }

    @NotNull
    private static LinkedHashMap<String, Object> loadDisplayPropertiesFromWellknown(VCCredentialResponse vcCredentialResponse, CredentialsSupportedResponse credentialsSupportedResponse, String locale) {
        LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();

        LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();
        credentialSubject.keySet().forEach(VCProperty -> {
            Optional<CredentialIssuerDisplayResponse> filteredResponse = credentialSubject.get(VCProperty)
                    .getDisplay().stream()
                    .filter(obj ->
                        LocaleUtils.matchesLocale(obj.getLocale(), locale)
                    )
                    .findFirst();
            String filteredValue = filteredResponse.isPresent() ? filteredResponse.get().getName() : "" ;
            vcPropertiesFromWellKnown.put(VCProperty, filteredValue);
        });

        List<String> orderProperty = credentialsSupportedResponse.getOrder();

        List<String> fieldProperties = orderProperty == null ? new ArrayList<>(vcPropertiesFromWellKnown.keySet()) : orderProperty;
        fieldProperties.forEach(vcProperty -> {
            if(credentialProperties.get(vcProperty) != null) {
                displayProperties.put(vcProperty,Map.of(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty)));
            }
        });
        return displayProperties;
    }


    private Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl, String credentialValidity, String locale) throws IOException, WriterException {
        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();
        String backgroundColor = credentialsSupportedResponse.getDisplay().get(0).getBackgroundColor();
        String backgroundImage = credentialsSupportedResponse.getDisplay().get(0).getBackgroundImage().getUri();
        String textColor = credentialsSupportedResponse.getDisplay().get(0).getTextColor();
        String credentialSupportedType = credentialsSupportedResponse.getDisplay().get(0).getName();
        String face = vcCredentialResponse.getCredential().getCredentialSubject().get("face") != null ? (String) vcCredentialResponse.getCredential().getCredentialSubject().get("face") : null;

        displayProperties.entrySet().stream()
                .forEachOrdered(entry -> {
                    String originalKey = entry.getKey();
                    Object entryValue = entry.getValue();

                    // Process the inner map
                    ((Map<?, ?>) entryValue).entrySet().stream()
                            .forEachOrdered(innerEntry -> {
                                String propertyKey = innerEntry.getKey().toString();
                                Object currentValue = innerEntry.getValue();
                                String value = "";

                                if (currentValue instanceof Map) {
                                    // If the value is a Map, handle it as a Map
                                    value = handleMap(currentValue);
                                } else if (currentValue instanceof List) {
                                    // If the value is a List, handle it as a List
                                    value = handleList(currentValue);
                                } else {
                                    // Otherwise, just convert to string
                                    value = currentValue.toString();
                                }

                                // Put the result into the rowProperties map
                                rowProperties.put(originalKey, Map.of(propertyKey, value));
                            });

                });
        String qrCodeImage = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl) :
                QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type()) ? constructQRCodeWithVCData(vcCredentialResponse) : "";
        data.put("qrCodeImage", qrCodeImage);
        data.put("credentialValidity", credentialValidity);
        data.put("logoUrl", issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
        data.put("rowProperties", rowProperties);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("backgroundImage", backgroundImage);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);
        return data;
    }

    private String handleList(Object list) {
        if (list instanceof List) {
            List<?> castedList = (List<?>) list;
            if (castedList.isEmpty()) return "";
            if (castedList.get(0) instanceof String) {
                return castedList.stream().map(String.class::cast).collect(Collectors.joining(", "));
            } else if (castedList.get(0) instanceof Map) {
                return ((List<Map<?, ?>>) castedList).stream()
                        .filter(obj -> obj.containsKey("language"))
                        .map(obj -> obj.get("value").toString())
                        .findFirst()
                        .orElse("");
            }
        }
        return "";
    }

    private String handleMap(Object map) {
        if (map instanceof Map) {
            return Optional.ofNullable(((Map<?, ?>) map).get("value"))
                    .map(Object::toString)
                    .orElse("");
        }
        return "";
    }

    @NotNull
    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data, String issuerId, String credentialType) throws IOException {
        String  credentialTemplate = utilities.getCredentialSupportedTemplateString(issuerId, credentialType);
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
        BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
        return Utilities.encodeToString(qrImage, "png");
    }

    private String constructQRCodeWithVCData(VCCredentialResponse vcCredentialResponse) throws JsonProcessingException, WriterException {
        String qrData = pixelPass.generateQRData(objectMapper.writeValueAsString(vcCredentialResponse.getCredential()), "");
        if (allowedQRDataSizeLimit > qrData.length()) {
            return constructQRCode(qrData);
        }
        return "";
    }

    private String constructQRCodeWithAuthorizeRequest(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws WriterException, JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = presentationService.constructPresentationDefinition(vcCredentialResponse);
        String presentationString = objectMapper.writeValueAsString(presentationDefinitionDTO);
        String qrData = String.format(ovpQRDataPattern, URLEncoder.encode(dataShareUrl, StandardCharsets.UTF_8), URLEncoder.encode(presentationString, StandardCharsets.UTF_8));
        return constructQRCode(qrData);
    }
}
