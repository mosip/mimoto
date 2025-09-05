package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.github.jknack.handlebars.Handlebars;
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
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.mosip.injivcrenderer.InjiVcRenderer;
import org.springframework.web.client.RestTemplate;

import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import java.util.Map;
import java.util.Properties;

@Slf4j
@Service
public class CredentialPDFGeneratorService {

    private record SelectedFace(String key, String face) {}

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

    @Autowired
    private InjiVcRenderer injiVcRenderer;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    private String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:4096}")
    Integer allowedQRDataSizeLimit;

    @Value("${mosip.injiweb.vc.subject.face.keys.order:image,face,photo,picture,portrait}")
    private String faceImageLookupKeys;

    @Value("${mosip.injiweb.mask.disclosures:true}")
    private boolean maskDisclosures;

    public ByteArrayInputStream generatePdfForVerifiableCredential(String credentialConfigurationId, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {
        // ByteArrayInputStream renderedVcStream = renderVcWithInjiRender(vcCredentialResponse);
        ByteArrayInputStream renderedVcStream = renderVcWithHandlebars(vcCredentialResponse);
        if (renderedVcStream != null) {
            return renderedVcStream;
        }

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

        SelectedFace selectedFace = extractFace(vcCredentialResponse);
        String face = selectedFace.face();
        String selectedFaceKey = selectedFace.key();

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
        displayProperties.forEach((key, valueMap) -> {
            boolean isFaceKey = selectedFaceKey != null && key.trim().equals(selectedFaceKey);

            valueMap.forEach((display, val) -> {
                String displayName = display.getName();
                String locale = display.getLocale();
                String strVal = formatValue(val, locale);
                if (disclosures.contains(key)) {
                    disclosuresProps.put(key, displayName);
                    if (maskDisclosures) {
                        strVal = utilities.maskValue(strVal);
                    }
                }
                if (!isFaceKey && displayName != null) {
                    rowProperties.put(key, Map.of(displayName, strVal));
                }
            });
        });

        String qrCodeImage = "";
        if (QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl);
        } else if (QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithVCData(vcCredentialResponse);
        }

        // is sd-jwt and has disclosures
        boolean isSdJwtWithDisclosures = CredentialFormat.VC_SD_JWT.getFormat().equals(vcCredentialResponse.getFormat()) && CollectionUtils.isNotEmpty(disclosures);

        data.put("isMaskedOn", maskDisclosures);
        data.put("isSdJwtWithDisclosures", isSdJwtWithDisclosures);
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

    private SelectedFace extractFace(VCCredentialResponse vcCredentialResponse) {
        // Use the appropriate credentialFormatHandler to extract credential properties
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());
        Map<String, Object> credentialSubject = credentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // handling face extraction based on configured keys
        List<String> faceKeys = Arrays.asList(faceImageLookupKeys.split(","));
        for (String faceKey : faceKeys) {
            String trimmedKey = faceKey.trim();
            Object faceValue = credentialSubject.get(trimmedKey);
            if (faceValue != null && !faceValue.toString().isEmpty()) {
                log.debug("Found face data using key: '{}'", trimmedKey);
                // Return the trimmedKey directly
                return new SelectedFace(trimmedKey, faceValue.toString());
            }
        }
        return new SelectedFace(null, null);
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
                        .filter(Objects::nonNull)
                        .map(item -> (Map<?, ?>) item)
                        .filter(m -> {
                            Object lang = m.get("language");  // Safely get language
                            return lang != null && LocaleUtils.matchesLocale(lang.toString(), locale);
                        })
                        .map(m -> {
                            Object value = m.get("value");  // Safely get value
                            return value != null ? value.toString() : null;
                        })
                        .filter(Objects::nonNull)
                        .findFirst()
                        .orElse("");
            }
        }
        return val != null ? val.toString() : "";
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

    private ByteArrayInputStream renderVcWithInjiRender(VCCredentialResponse vcCredentialResponse) throws JsonProcessingException {
        // Parsing renderMethod with strict typing
        if (vcCredentialResponse.getCredential() == null) {
            return null;
        }
        // Convert VCCredentialResponse.credential to JSON string
        String vcJson = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());

        @SuppressWarnings("unchecked")
        Map<String, Object> credentialMap = objectMapper.convertValue(vcCredentialResponse.getCredential(),
                new TypeReference<Map<String, Object>>() {
                });
        List<Map<String, Object>> renderMethod = objectMapper.convertValue(credentialMap.get("renderMethod"),
                new TypeReference<List<Map<String, Object>>>() {
                });

        if (CollectionUtils.isEmpty(renderMethod)) {
            return null;
        }

        // Process first render method (assuming it's the primary one)
        Map<String, Object> method = renderMethod.getFirst();
        String renderSuite = (String) method.get("renderSuite");

        @SuppressWarnings("unchecked")
        Map<String, Object> template = (Map<String, Object>) method.get("template");

        if (template != null && "svg-mustache".equals(renderSuite)) {
            List<String> svgImage = injiVcRenderer.renderSvg(vcJson);
            return convertSvgToPdf(svgImage.getFirst());
        }
        return null;
    }

    private ByteArrayInputStream convertSvgToPdf(String svgImage) {
        if (StringUtils.isEmpty(svgImage)) {
            return null;
        }

        // considering only first svg from the list
        String svgContent = String.join("\n", svgImage);

        // Convert SVG to PDF
        try (ByteArrayOutputStream pdfOutputStream = new ByteArrayOutputStream();
             PdfWriter pdfWriter = new PdfWriter(pdfOutputStream)) {

            String html = "<html><body>" + svgContent + "</body></html>";
            ConverterProperties converterProperties = new ConverterProperties();
            converterProperties.setFontProvider(new DefaultFontProvider(true, false, false));
            HtmlConverter.convertToPdf(html, pdfWriter, converterProperties);

            return new ByteArrayInputStream(pdfOutputStream.toByteArray());
        } catch (IOException e) {
            log.error("Error converting SVG to PDF: {}", e.getMessage());
            throw new RuntimeException("Failed to convert SVG to PDF", e);
        }
    }

    private ByteArrayInputStream renderVcWithHandlebars(VCCredentialResponse vcCredentialResponse) {
        // Parsing renderMethod with strict typing
        if (vcCredentialResponse.getCredential() == null) {
            return null;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> credentialMap = objectMapper.convertValue(vcCredentialResponse.getCredential(),
                new TypeReference<Map<String, Object>>() {
                });
        List<Map<String, Object>> renderMethod = objectMapper.convertValue(credentialMap.get("renderMethod"),
                new TypeReference<List<Map<String, Object>>>() {
                });
        Map<String, Object> credentialSubject = objectMapper.convertValue(credentialMap.get("credentialSubject"),
                new TypeReference<Map<String, Object>>() {
                });

        if (CollectionUtils.isEmpty(renderMethod) || MapUtils.isEmpty(credentialSubject)) {
            return null;
        }

        // Process first render method (assuming it's the primary one)
        Map<String, Object> method = renderMethod.getFirst();
        @SuppressWarnings("unchecked")
        Map<String, Object> template = (Map<String, Object>) method.get("template");
        String renderSuite = (String) method.get("renderSuite");

        if (template != null && "svg-mustache".equals(renderSuite)) {
            String svgTemplateUri = (String) template.get("id");
            String svgTemplate = getSvgTemplate(svgTemplateUri);
//            String svgTemplate = """
//            Crops: {{/credentialSubject/crops/*/cropName}}
//
//            Single line access: {{/credentialSubject/phoneNumber}}
//            """;
            Map<String, Object> templateData = prepareTemplateData(credentialSubject);

            String renderedSvg = renderSvgWithHandlebars(svgTemplate, templateData);
            return convertSvgToPdf(renderedSvg);
        }
        return null;
    }

    private String getSvgTemplate(String svgTemplateUri) {
        try {
            String svgTemplate = restTemplate.getForObject(svgTemplateUri, String.class);
            if (svgTemplate == null) {
                log.error("Failed to fetch SVG template from URI: {}", svgTemplateUri);
                return null;
            }
            return svgTemplate;
        } catch (Exception e) {
            log.error("Error fetching SVG template from URI {}: {}", svgTemplateUri, e.getMessage());
            throw new RuntimeException("Failed to fetch SVG template", e);
        }
    }

    private Map<String, Object> prepareTemplateData(Map<String, Object> credentialSubject) {
        Map<String, Object> credential = Map.of("credentialSubject", credentialSubject);
        return credential;
        /*
        // Add all credential subject data directly
        data.putAll(credentialSubject);

        // todo: generalize based on type and flatten
        // Handle special cases for nested objects
        if (credentialSubject.get("address") instanceof Map) {
            Map<String, Object> address = (Map<String, Object>) credentialSubject.get("address");
            // Flatten address fields or keep as is based on template needs
            data.put("address", address);
        }

        // Handle arrays/lists
        if (credentialSubject.get("crops") instanceof List) {
            List<String> crops = (List<String>) credentialSubject.get("crops");
            data.put("crops", crops);
        }

        // Handle nested objects with units
        if (credentialSubject.get("totalLandArea") instanceof Map) {
            Map<String, Object> landArea = (Map<String, Object>) credentialSubject.get("totalLandArea");
            // You might want to format this as a string with unit
            data.put("totalLandArea", landArea);
        }

        // Handle special cases like face image
        if (credentialSubject.containsKey("face")) {
            data.put("face", credentialSubject.get("face"));
        }

        return data;
         */
    }

    private String renderSvgWithHandlebars(String template, Map<String, Object> data) {
        try {
            Handlebars handlebars = new Handlebars();
            handlebars.setStartDelimiter("{{");
            handlebars.setEndDelimiter("}}");

            // Register helper to handle forward slash notation
            handlebars.registerHelper("get", (context, options) -> {
                String path = options.fn.text();
                if (path.startsWith("/")) {
                    path = path.substring(1); // Remove leading slash
                }
                String[] parts = path.split("/");
                Object current = context;

                for (String part : parts) {
                    if (part.equals("*")) {
                        // Handle array wildcard
                        if (current instanceof List<?>) {
                            List<?> list = (List<?>) current;
                            return list.stream()
                                    .map(item -> String.valueOf(getValueForPath(item,
                                            Arrays.copyOfRange(parts,
                                                    Arrays.asList(parts).indexOf("*") + 1,
                                                    parts.length))))
                                    .filter(Objects::nonNull)
                                    .collect(Collectors.joining(", "));
                        }
                    } else if (current instanceof Map) {
                        current = ((Map<?, ?>) current).get(part);
                    }
                }
                return current != null ? current.toString() : "";
            });

            // Convert template to use the custom helper
            String modifiedTemplate = template.replaceAll("\\{\\{(/[^}]+)\\}\\}", "{{#get}}$1{{/get}}");

            com.github.jknack.handlebars.Template hbsTemplate = handlebars.compileInline(modifiedTemplate);
            return hbsTemplate.apply(data);
        } catch (IOException e) {
            log.error("Error rendering Handlebars template: {}", e.getMessage());
            throw new RuntimeException("Failed to render Handlebars template", e);
        }
    }

    private Object getValueForPath(Object obj, String[] remainingPath) {
        Object current = obj;
        for (String part : remainingPath) {
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
            } else {
                return null;
            }
        }
        return current;
    }

}

