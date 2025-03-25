package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.SigningAlgorithm;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.*;
import io.mosip.pixelpass.PixelPass;
import io.mosip.pixelpass.exception.QrDataOverflowException;
import io.mosip.pixelpass.types.ECC;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
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

    private static final ECC DEFAULT_ECC_LEVEL = ECC.L;

    @Autowired
    private Utilities utilities;


    @Autowired
    IssuersService issuersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

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

    @Autowired
    private CredentialUtilService credentialUtilService;

    @PostConstruct
    public void init() {
        pixelPass = new PixelPass();
        credentialsVerifier = new CredentialsVerifier();
    }

    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        VCCredentialRequest vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token(), null, null, false
        );
        VCCredentialResponse vcCredentialResponse = credentialUtilService.downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || credentialUtilService.verifyCredential(vcCredentialResponse);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            return generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
        throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }

    public ByteArrayInputStream generatePdfForVerifiableCredentials(String credentialType, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = loadDisplayPropertiesFromWellknown(vcCredentialResponse, credentialsSupportedResponse, locale);
        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse, vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity);
        return renderVCInCredentialTemplate(data, issuerDTO.getIssuer_id(), credentialType);
    }

    @NotNull
    private static LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(VCCredentialResponse vcCredentialResponse, CredentialsSupportedResponse credentialsSupportedResponse, String userLocale) {
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();
        LinkedHashMap<String, CredentialIssuerDisplayResponse> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();
        String locale = LocaleUtils.resolveLocaleWithFallback(credentialSubject, userLocale);
        if (locale != null) {
            credentialSubject.keySet().forEach(VCProperty -> {
                Optional<CredentialIssuerDisplayResponse> filteredResponse = credentialSubject.get(VCProperty)
                        .getDisplay().stream()
                        .filter(obj -> LocaleUtils.matchesLocale(obj.getLocale(), locale))
                        .findFirst();

                if (filteredResponse.isPresent()) {
                    CredentialIssuerDisplayResponse filteredValue = filteredResponse.get();
                    vcPropertiesFromWellKnown.put(VCProperty, filteredValue);
                }
            });
        }

        List<String> orderProperty = credentialsSupportedResponse.getOrder();

        List<String> fieldProperties = orderProperty == null ? new ArrayList<>(vcPropertiesFromWellKnown.keySet()) : orderProperty;
        fieldProperties.forEach(vcProperty -> {
            if (vcPropertiesFromWellKnown.get(vcProperty) != null && credentialProperties.get(vcProperty) != null) {
                displayProperties.put(vcProperty, Map.of(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty)));
            }
        });
        return displayProperties;
    }


    private Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl, String credentialValidity) throws IOException {
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
                    Map<CredentialIssuerDisplayResponse, Object> properties = entry.getValue();

                    // Process the inner map
                    ((Map<CredentialIssuerDisplayResponse, ?>) properties).entrySet().stream()
                            .forEachOrdered(innerEntry -> {
                                // loadDisplayPropertiesFromWellknown method returns both name and locale field values of the matching display obj in the response
                                CredentialIssuerDisplayResponse matchingWellknownDisplayObj = innerEntry.getKey();
                                String nameFromDisplayObj = matchingWellknownDisplayObj.getName();
                                String localeFromDisplayObj = matchingWellknownDisplayObj.getLocale();
                                Object propertyValFromDownloadedVcResponse = innerEntry.getValue();
                                String value = "";

                                if (propertyValFromDownloadedVcResponse instanceof Map) {
                                    // If the value is a Map, handle it as a Map
                                    value = handleMap(propertyValFromDownloadedVcResponse);
                                } else if (propertyValFromDownloadedVcResponse instanceof List) {
                                    // If the value is a List, handle it as a List
                                    value = handleList(propertyValFromDownloadedVcResponse, localeFromDisplayObj);
                                } else {
                                    // Otherwise, just convert to string
                                    value = propertyValFromDownloadedVcResponse.toString();
                                }

                                // Put the result into the rowProperties map
                                rowProperties.put(originalKey, Map.of(nameFromDisplayObj, value));
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

    private String handleList(Object list, String locale) {
        List<?> castedList = (List<?>) list;
        String response = "";
        if (castedList.isEmpty()) return "";
        if (castedList.get(0) instanceof String) {
            response = castedList.stream().map(String.class::cast).collect(Collectors.joining(", "));
        } else if (castedList.get(0) instanceof Map) {
            response = ((List<Map<?, ?>>) castedList).stream()
                    .filter(obj -> LocaleUtils.matchesLocale(obj.get("language").toString(), locale))
                    .map(obj -> obj.get("value").toString())
                    .findFirst()
                    .orElse("");
        }
        return response;
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
    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data, String issuerId, String credentialType) {
        String credentialTemplate = utilities.getCredentialSupportedTemplateString(issuerId, credentialType);
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

    private String constructQRCodeWithVCData(VCCredentialResponse vcCredentialResponse) throws JsonProcessingException {
        try {
            String qrData = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());
            return pixelPass.generateQRCodeWithinLimit(allowedQRDataSizeLimit, qrData, DEFAULT_ECC_LEVEL, "");
        } catch (QrDataOverflowException e) {
            log.warn("QR data exceeds the allowed limit", allowedQRDataSizeLimit);
            return "";
        }
    }

    private String constructQRCodeWithAuthorizeRequest(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = presentationService.constructPresentationDefinition(vcCredentialResponse);
        String presentationString = objectMapper.writeValueAsString(presentationDefinitionDTO);
        String qrData = String.format(ovpQRDataPattern, URLEncoder.encode(dataShareUrl, StandardCharsets.UTF_8), URLEncoder.encode(presentationString, StandardCharsets.UTF_8));
         return pixelPass.generateQRCode(qrData, DEFAULT_ECC_LEVEL, "");
    }
}
