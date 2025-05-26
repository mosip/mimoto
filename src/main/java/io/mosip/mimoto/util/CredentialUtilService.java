package io.mosip.mimoto.util;

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
import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.model.SigningAlgorithm;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
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
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_FETCH_EXCEPTION;

@Slf4j
@Service
public class CredentialUtilService {
    @Autowired
    IdpService idpService;

    @Autowired
    RestTemplate restTemplate;

    @Autowired
    IssuersService issuersService;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    JoseUtil joseUtil;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    CredentialsVerifier credentialsVerifier;

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
    PixelPass pixelPass;

    @PostConstruct
    public void init() {
        credentialsVerifier = new CredentialsVerifier();
        pixelPass = new PixelPass();
    }

    public TokenResponseDTO getTokenResponse(VerifiableCredentialRequestDTO verifiableCredentialRequest, String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        return getTokenResponse(convertVerifiableCredentialRequestToMap(verifiableCredentialRequest), issuerId);
    }

    public TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        String tokenEndpoint = idpService.getTokenEndpoint(credentialIssuerConfiguration);
        HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO, tokenEndpoint);
        TokenResponseDTO response = restTemplate.postForObject(tokenEndpoint, request, TokenResponseDTO.class);
        if (response == null) {
            throw new IdpException("Exception occurred while performing the authorization");
        }
        return response;
    }

    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException {
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        log.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null)
            throw new InvalidCredentialResourceException("VC Credential Issue API not accessible");
        return vcCredentialResponse;
    }

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken, String walletId, String base64EncodedWalletKey, Boolean isLoginFlow) throws Exception {
        String jwt;

        Map<String, ProofTypesSupported> proofTypesSupported = credentialsSupportedResponse.getProofTypesSupported();
        SigningAlgorithm algorithm;
        if (proofTypesSupported.containsKey("jwt")) {
            algorithm = SigningAlgorithm.fromString(proofTypesSupported.get("jwt").getProofSigningAlgValuesSupported().getFirst());
        } else {
            algorithm = SigningAlgorithm.RS256;
        }

        if (!isLoginFlow) {
            jwt = joseUtil.generateJwt(credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        } else {
            Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name());
            byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
            SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
            byte[] publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
            byte[] privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());
            jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(algorithm, credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken, publicKeyBytes, privateKeyInBytes);
        }
        List<String> credentialContext = credentialsSupportedResponse.getCredentialDefinition().getContext();

        if (credentialContext == null || credentialContext.isEmpty()) {
            credentialContext = List.of("https://www.w3.org/2018/credentials/v1");
        }

        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(credentialContext)
                        .build())
                .build();
    }

    public Boolean verifyCredential(VCCredentialResponse vcCredentialResponse) throws VCVerificationException, JsonProcessingException {
        log.info("Initiated the VC Verification : Started");
        String credentialString = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());
        VerificationResult verificationResult = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        if (!verificationResult.getVerificationStatus()) {
            throw new VCVerificationException(verificationResult.getVerificationErrorCode().toLowerCase(), verificationResult.getVerificationMessage());
        }
        log.info("Completed the VC Verification : Completed -> result : " + verificationResult);
        return true;
    }

    @NotNull
    public static LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(VCCredentialResponse vcCredentialResponse, CredentialsSupportedResponse credentialsSupportedResponse, String userLocale) {
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

    public Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl, String credentialValidity) throws IOException, WriterException {
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

    public ByteArrayInputStream generatePdfForVerifiableCredentials(String credentialType, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = loadDisplayPropertiesFromWellknown(vcCredentialResponse, credentialsSupportedResponse, locale);
        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse, vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity);
        return renderVCInCredentialTemplate(data, issuerDTO.getIssuer_id(), credentialType);
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

    public WalletCredentialResponseDTO generateCredentialResponse(String decryptedCredential, CredentialMetadata credentialMetadata, String locale) throws CredentialProcessingException {
        log.info("Generating credential response for issuerId: {}, credentialType: {}", credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType());
        try {
            // Parse decrypted credential
            VCCredentialResponse vcCredentialResponse = objectMapper.readValue(decryptedCredential, VCCredentialResponse.class);

            // Fetch issuer details
            IssuerDTO issuerDTO = issuersService.getIssuerDetails(credentialMetadata.getIssuerId());

            // Fetch issuer configuration
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType());

            // Find credentials supported response for the credential type
            CredentialsSupportedResponse credentialsSupportedResponse = issuerConfig.getCredentialsSupportedResponse();
            if (credentialsSupportedResponse == null || !credentialsSupportedResponse.getCredentialDefinition().getType().contains(credentialMetadata.getCredentialType())) {
                log.error("Credentials supported response not found for credentialType: {}", credentialMetadata.getCredentialType());
                throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Invalid credential type configuration");
            }

            // Generate PDF
            // keep the datashare url and credential validity as defaults in downloading VC as PDF as logged-in user
            // This is because generatePdfForVerifiableCredentials will be used by both logged-in and non-logged-in users
            ByteArrayInputStream pdfStream = generatePdfForVerifiableCredentials(
                    credentialMetadata.getCredentialType(),
                    vcCredentialResponse,
                    issuerDTO,
                    credentialsSupportedResponse,
                    "",
                    "-1",
                    locale
            );

            // Construct response
            String fileName = String.format("%s_credential.pdf", credentialMetadata.getCredentialType());
            return WalletCredentialResponseDTO.builder()
                    .fileName(fileName)
                    .fileContentStream(new InputStreamResource(pdfStream))
                    .build();
        } catch (JsonProcessingException e) {
            log.error("Failed to parse decrypted credential for issuerId: {}, credentialType: {}", credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to parse decrypted credential");
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException | InvalidIssuerIdException e) {
            log.error("Failed to fetch issuer details or configuration for issuerId: {}", credentialMetadata.getIssuerId(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to fetch issuer configuration");
        } catch (Exception e) {
            log.error("Failed to generate PDF for credentialType: {}", credentialMetadata.getCredentialType(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to generate credential PDF");
        }
    }

    private Map<String, String> convertVerifiableCredentialRequestToMap(VerifiableCredentialRequestDTO verifiableCredentialRequest) {
        Map<String, String> params = new HashMap<>();
        params.put("code", verifiableCredentialRequest.getCode());
        params.put("redirect_uri", verifiableCredentialRequest.getRedirectUri());
        params.put("grant_type", verifiableCredentialRequest.getGrantType());
        params.put("code_verifier", verifiableCredentialRequest.getCodeVerifier());

        return params;
    }
}


