package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
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
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
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

import java.util.Map;
import java.util.Properties;

@Slf4j
@Service
public class CredentialPDFGeneratorService {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PresentationServiceImpl presentationService;

    @Autowired
    private Utilities utilities;

    @Autowired
    private PixelPass pixelPass;

    @Autowired
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    private String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:4096}")
    Integer allowedQRDataSizeLimit;

    public ByteArrayInputStream generatePdfForVerifiableCredential(String credentialConfigurationId, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {

        // Get the appropriate processor based on format
        CredentialFormatHandler processor = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());

        // Extract credential properties using the specific processor
        Map<String, Object> credentialProperties = processor.extractCredentialClaims(vcCredentialResponse);

        // Load display properties using the specific processor
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties =
                processor.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, locale);

        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,
                vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity);

        return renderVCInCredentialTemplate(data, issuerDTO.getIssuer_id(), credentialConfigurationId);
    }

    private Map<String, Object> getPdfResourceFromVcProperties(
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            VCCredentialResponse vcCredentialResponse,
            IssuerDTO issuerDTO,
            String dataShareUrl,
            String credentialValidity) throws IOException, WriterException {

        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();

        CredentialSupportedDisplayResponse firstDisplay = Optional.ofNullable(credentialsSupportedResponse.getDisplay())
                .filter(list -> !list.isEmpty())
                .map(List::getFirst)
                .orElse(null);

        String backgroundColor = firstDisplay != null ? firstDisplay.getBackgroundColor() : null;
        String backgroundImage = firstDisplay != null && firstDisplay.getBackgroundImage() != null
                ? firstDisplay.getBackgroundImage().getUri()
                : null;
        String textColor = firstDisplay != null ? firstDisplay.getTextColor() : null;
        String credentialSupportedType = firstDisplay != null ? firstDisplay.getName() : null;

        String face = extractFace(vcCredentialResponse);
        Set<String> disclosures;
        if (CredentialFormat.VC_SD_JWT.getFormat().equals(vcCredentialResponse.getFormat())) {
            SDJWT sdjwt = SDJWT.parse((String) vcCredentialResponse.getCredential());
            disclosures = sdjwt.getDisclosures().stream()
                    .map(Disclosure::getClaimName)
                    .collect(Collectors.toSet());
        } else {
            disclosures = new LinkedHashSet<>();
        }

        LinkedHashMap<String, String> disclosuresProps = new LinkedHashMap<>();
        displayProperties.forEach((key, valueMap) -> valueMap.forEach((display, val) -> {
            String displayName = display.getName();
            String locale = display.getLocale();
            String strVal = formatValue(val, locale);
            if (disclosures.contains(key)){
                disclosuresProps.put(key, displayName);
                rowProperties.put(key, Map.of(displayName, strVal));
            } else{
                rowProperties.put(key, Map.of(displayName, strVal));
            }

        }));

        String qrCodeImage = "";
        if (QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl);
        } else if (QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithVCData(vcCredentialResponse);
        }

        data.put("qrCodeImage", qrCodeImage);
        data.put("credentialValidity", credentialValidity);
        data.put("logoUrl", issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
        data.put("rowProperties", rowProperties);
        data.put("disclosures", disclosuresProps);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("backgroundImage", backgroundImage);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);
        return data;
    }

    private String extractFace(VCCredentialResponse vcCredentialResponse) {
        // Use the appropriate credentialFormatHandler to extract credential properties
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());
        Map<String, Object> credentialSubject = credentialFormatHandler.extractCredentialClaims(vcCredentialResponse);
        Object face = credentialSubject.get("face");
        return face != null ? face.toString() : null;
    }

    private String formatValue(Object val, String locale) {
        if (val instanceof Map) {
            return Optional.ofNullable(((Map<?, ?>) val).get("value")).map(Object::toString).orElse("");
        } else if (val instanceof List) {
            List<?> list = (List<?>) val;
            if (list.isEmpty()) return "";
            if (list.getFirst() instanceof String) {
                return String.join(", ", (List<String>) list);
            } else if (list.getFirst() instanceof Map<?, ?>) {
                return list.stream()
                        .map(item -> (Map<?, ?>) item)
                        .filter(m -> LocaleUtils.matchesLocale(m.get("language").toString(), locale))
                        .map(m -> m.get("value").toString())
                        .findFirst()
                        .orElse("");
            }
        }
        return val.toString();
    }

    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data, String issuerId, String credentialConfigurationId) {
        String credentialTemplate = utilities.getCredentialSupportedTemplateString(issuerId, credentialConfigurationId);
        Properties props = new Properties();
        props.setProperty("resource.loader", "class");
        props.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        Velocity.init(props);
        VelocityContext velocityContext = new VelocityContext(data);

        StringWriter writer = new StringWriter();
        Velocity.evaluate(velocityContext, writer, "Credential Template", credentialTemplate);

        String mergedHtml = writer.toString();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        PdfWriter pdfwriter = new PdfWriter(outputStream);
        DefaultFontProvider defaultFont = new DefaultFontProvider(true, false, false);
        ConverterProperties converterProperties = new ConverterProperties();
        converterProperties.setFontProvider(defaultFont);
        HtmlConverter.convertToPdf(mergedHtml, pdfwriter, converterProperties);
        return new ByteArrayInputStream(outputStream.toByteArray());
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


