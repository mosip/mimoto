package io.mosip.mimoto.service;

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
import io.mosip.mimoto.dto.mimoto.CredentialDisplayResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class CredentialPDFGeneratorService {

    @Autowired
    ObjectMapper objectMapper;

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

    @Autowired
    private Utilities utilities;

    @Autowired
    private PixelPass pixelPass;


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

    private Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl, String credentialValidity) throws IOException, WriterException {
        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();
        String backgroundColor = credentialsSupportedResponse.getDisplay().getFirst().getBackgroundColor();
        String backgroundImage = credentialsSupportedResponse.getDisplay().getFirst().getBackgroundImage().getUri();
        String textColor = credentialsSupportedResponse.getDisplay().getFirst().getTextColor();
        String credentialSupportedType = credentialsSupportedResponse.getDisplay().getFirst().getName();
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

        String qrCodeImage;
        if (QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type())) {
            // Login flow
            if (dataShareUrl.isEmpty()) {
                qrCodeImage = constructQRCodeWithVCData(vcCredentialResponse);
            } else {
                qrCodeImage = constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl);
            }
        } else if (QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithVCData(vcCredentialResponse);
        } else {
            qrCodeImage = "";
        }

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

    private String handleList(Object list, String locale) {
        List<?> castedList = (List<?>) list;
        String response = "";
        if (castedList.isEmpty()) return "";
        if (castedList.getFirst() instanceof String) {
            response = castedList.stream().map(String.class::cast).collect(Collectors.joining(", "));
        } else if (castedList.getFirst() instanceof Map) {
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

    private String constructQRCode(String qrData) throws WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
        return Utilities.encodeToString(qrImage, "png");
    }



}


