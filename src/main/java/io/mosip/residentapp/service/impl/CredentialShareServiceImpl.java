package io.mosip.residentapp.service.impl;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.gson.Gson;

import org.joda.time.DateTime;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import io.mosip.biometrics.util.CommonUtil;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.residentapp.constant.BiometricType;
import io.mosip.residentapp.constant.DocumentGeneratorExceptionCodeConstant;
import io.mosip.residentapp.constant.EventId;
import io.mosip.residentapp.constant.EventName;
import io.mosip.residentapp.constant.EventType;
import io.mosip.residentapp.constant.IdType;
import io.mosip.residentapp.constant.LoggerFileConstant;
import io.mosip.residentapp.constant.ModuleName;
import io.mosip.residentapp.constant.PlatformSuccessMessages;
import io.mosip.residentapp.dto.mosip.CryptoWithPinRequestDto;
import io.mosip.residentapp.dto.mosip.CryptoWithPinResponseDto;
import io.mosip.residentapp.dto.mosip.DataShare;
import io.mosip.residentapp.dto.mosip.JsonValue;
import io.mosip.residentapp.entity.BDBInfo;
import io.mosip.residentapp.entity.BIR;
import io.mosip.residentapp.exception.ApiNotAccessibleException;
import io.mosip.residentapp.exception.CryptoManagerException;
import io.mosip.residentapp.exception.DataShareException;
import io.mosip.residentapp.exception.DocumentGeneratorException;
import io.mosip.residentapp.exception.ExceptionUtils;
import io.mosip.residentapp.exception.IdentityNotFoundException;
import io.mosip.residentapp.exception.ParsingException;
import io.mosip.residentapp.exception.PlatformErrorMessages;
import io.mosip.residentapp.exception.UINNotFoundInDatabase;
import io.mosip.residentapp.exception.VidCreationException;
import io.mosip.residentapp.model.CredentialStatusEvent;
import io.mosip.residentapp.model.EventModel;
import io.mosip.residentapp.model.StatusEvent;
import io.mosip.residentapp.service.CredentialShareService;
import io.mosip.residentapp.service.RestClientService;
import io.mosip.residentapp.spi.CbeffUtil;
import io.mosip.residentapp.util.AuditLogRequestBuilder;
import io.mosip.residentapp.util.CbeffToBiometricUtil;
import io.mosip.residentapp.util.CryptoCoreUtil;
import io.mosip.residentapp.util.CryptoUtil;
import io.mosip.residentapp.util.DataShareUtil;
import io.mosip.residentapp.util.DateUtils;
import io.mosip.residentapp.util.JsonUtil;
import io.mosip.residentapp.util.LogDescription;
import io.mosip.residentapp.util.LoggerUtil;
import io.mosip.residentapp.util.RestApiClient;
import io.mosip.residentapp.util.Utilities;
import io.mosip.residentapp.util.WebSubSubscriptionHelper;

@Service
public class CredentialShareServiceImpl implements CredentialShareService {
    public static final String EVENT_JSON_FILE_NAME = "%s_EVENT.json";
    public static final String VC_JSON_FILE_NAME = "%s_%s_VC.json";
    public static final String CARD_JSON_FILE_NAME = "%s_%s_VCD.json";

    /** The Constant FINGER. */
    public static final String FINGER = "Finger";

    private Gson gson = new Gson();

    public String topic = "CREDENTIAL_STATUS_UPDATE";

    @Autowired
    public WebSubSubscriptionHelper webSubSubscriptionHelper;

    @Autowired
    public DataShareUtil dataShareUtil;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    public RestApiClient restApiClient;

    @Autowired
    public CryptoCoreUtil cryptoCoreUtil;

    /** The Constant FILE_SEPARATOR. */
    public static final String FILE_SEPARATOR = File.separator;

    /** The Constant VALUE. */
    public static final String VALUE = "value";

    /** The Constant UIN_CARD_TEMPLATE. */
    public static final String UIN_CARD_TEMPLATE = "RPR_UIN_CARD_TEMPLATE";

    /** The Constant MASKED_UIN_CARD_TEMPLATE. */
    public static final String MASKED_UIN_CARD_TEMPLATE = "RPR_MASKED_UIN_CARD_TEMPLATE";

    /** The Constant FACE. */
    public static final String FACE = "Face";

    /** The Constant UIN_TEXT_FILE. */
    public static final String UIN_TEXT_FILE = "textFile";

    /** The Constant APPLICANT_PHOTO. */
    public static final String APPLICANT_PHOTO = "ApplicantPhoto";

    /** The Constant UINCARDPASSWORD. */
    public static final String UINCARDPASSWORD = "mosip.registration.processor.print.service.uincard.password";

    private Logger logger = LoggerUtil.getLogger(CredentialShareServiceImpl.class);

    /** The core audit request builder. */
    @Autowired
    public AuditLogRequestBuilder auditLogRequestBuilder;

    /** The utilities. */
    @Autowired
    public Utilities utilities;

    /** The rest client service. */
    @Autowired
    public RestClientService<Object> restClientService;

    /** The Constant INDIVIDUAL_BIOMETRICS. */
    public static final String INDIVIDUAL_BIOMETRICS = "individualBiometrics";

    /** The Constant VID_CREATE_ID. */
    public static final String VID_CREATE_ID = "registration.processor.id.repo.generate";

    /** The Constant REG_PROC_APPLICATION_VERSION. */
    public static final String REG_PROC_APPLICATION_VERSION = "registration.processor.id.repo.vidVersion";

    /** The Constant DATETIME_PATTERN. */
    public static final String DATETIME_PATTERN = "mosip.print.datetime.pattern";

    public static final String NAME = "name";

    public static final String VID_TYPE = "registration.processor.id.repo.vidType";

    /** The cbeffutil. */
    @Autowired
    public CbeffUtil cbeffutil;

    /** The env. */
    @Autowired
    public Environment env;

    @Autowired
    public PublisherClient<String, Object, HttpHeaders> pb;

    @Value("${mosip.datashare.partner.id}")
    public String partnerId;

    @Value("${mosip.datashare.policy.id}")
    public String policyId;

    @Value("${mosip.template-language}")
    public String templateLang;

    @Value("#{'${mosip.mandatory-languages:}'.concat('${mosip.optional-languages:}')}")
    public String supportedLang;

    public boolean generateDocuments(EventModel eventModel) throws Exception {
        Path eventFilePath = Path.of(utilities.getDataPath(),
                String.format(EVENT_JSON_FILE_NAME, eventModel.getEvent().getTransactionId()));
        Files.write(eventFilePath, gson.toJson(eventModel).getBytes(), StandardOpenOption.CREATE);
        logger.info("Event data saved:: " + eventFilePath.toFile().getAbsolutePath());

        Map<String, byte[]> byteMap = new HashMap<>();
        String decodedCredential = null;
        String credentialSubject = null;
        String credential = null;

        try {
            if (eventModel.getEvent().getDataShareUri() == null || eventModel.getEvent().getDataShareUri().isEmpty()) {
                credential = eventModel.getEvent().getData().get("credential").toString();
            } else {
                String dataShareUrl = eventModel.getEvent().getDataShareUri();
                URI dataShareUri = URI.create(dataShareUrl);
                credential = restApiClient.getApi(dataShareUri, String.class);
            }
            String encryptionPin = eventModel.getEvent().getData().get("protectionKey").toString();
            decodedCredential = cryptoCoreUtil.decrypt(credential);
            @SuppressWarnings("unchecked")
            Map<String, String> proofMap = (Map<String, String>) eventModel.getEvent().getData().get("proof");
            String sign = proofMap.get("signature").toString();
    
            credentialSubject = getCredentialSubject(decodedCredential);

            org.json.JSONObject credentialJSON = decrypt(decodedCredential, credentialSubject, encryptionPin);
            String uin = credentialJSON.getString("UIN");
    
            Path vcTextFilePath = Path.of(utilities.getDataPath(),
                    String.format(VC_JSON_FILE_NAME, eventModel.getEvent().getTransactionId(), uin));
            Files.deleteIfExists(vcTextFilePath);
            Files.write(vcTextFilePath, gson.toJson(gson.fromJson(decodedCredential, TreeMap.class)).getBytes(), StandardOpenOption.CREATE);
    
            String credentialType = eventModel.getEvent().getData().get("credentialType").toString();
            byteMap = getDocuments(credentialJSON, credentialType, eventModel.getEvent().getTransactionId(), getSignature(sign, credential));
    
            Path textFilePath = Path.of(utilities.getDataPath(),
                    String.format(CARD_JSON_FILE_NAME, eventModel.getEvent().getTransactionId(), uin));
            Files.deleteIfExists(textFilePath);
            Files.write(textFilePath, byteMap.get(UIN_TEXT_FILE), StandardOpenOption.CREATE);
            logger.info("Generated files from event:: " + textFilePath.toFile().getAbsolutePath());
        } catch (Exception e){
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public org.json.JSONObject decrypt(String credential, String credentialSubject, String encryptionPin) {
        org.json.JSONObject decryptedJson;
        LogDescription description = new LogDescription();
        try {
            decryptedJson = decryptAttribute(new org.json.JSONObject(credentialSubject), encryptionPin, credential);
        } catch (Exception e) {
            description.setMessage(PlatformErrorMessages.RESIDENT_APP_VC_DECRYPTION_FAILED.getMessage());
            description.setCode(PlatformErrorMessages.RESIDENT_APP_VC_DECRYPTION_FAILED.getCode());
            logger.error(description.toString(), e);
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.VC_DECRYPTION_EXCEPTION.getErrorCode(),
                    e.getMessage() + ExceptionUtils.getStackTrace(e));
        }

        return decryptedJson;
    }

    public Map<String, byte[]> getDocuments(
            org.json.JSONObject credentialJSON,
            String credentialType,
            String requestId,
            String sign) {
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                "CredentialShareServiceImpl::getDocuments()::entry");

        Map<String, byte[]> byteMap = new HashMap<>();
        String uin = null;
        LogDescription description = new LogDescription();
        String individualBio = null;
        Map<String, Object> attributes = new LinkedHashMap<>();
        boolean isTransactionSuccessful = false;
        try {
            individualBio = credentialJSON.getString("biometrics");
            String individualBiometric = new String(individualBio);
            uin = credentialJSON.getString("UIN");
            setTemplateAttributes(credentialJSON.toString(), attributes);
            attributes.put(IdType.UIN.toString(), uin);

            byte[] textFileByte = createJSONFile(credentialJSON, individualBiometric, attributes);
            byteMap.put(UIN_TEXT_FILE, textFileByte);

            // TODO: Uncomment this after datashare creation API fixed.
            // statusUpdate(requestId, textFileByte, credentialType);
            isTransactionSuccessful = true;

        } catch (UINNotFoundInDatabase e) {
            description.setMessage(PlatformErrorMessages.RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE.getMessage());
            description.setCode(PlatformErrorMessages.RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE.getCode());

            logger.error(PlatformErrorMessages.RESIDENT_APP_UIN_NOT_FOUND_IN_DATABASE.name(), e);
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorCode(),
                    e.getErrorText());

        } catch (Exception e) {
            description.setMessage(PlatformErrorMessages.RESIDENT_APP_DOCUMENT_GENERATION_FAILED.getMessage());
            description.setCode(PlatformErrorMessages.RESIDENT_APP_DOCUMENT_GENERATION_FAILED.getCode());
            logger.error(description.toString(), e);
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorCode(),
                    e.getMessage() + ExceptionUtils.getStackTrace(e));

        } finally {
            String eventId = "";
            String eventName = "";
            String eventType = "";
            if (isTransactionSuccessful) {
                description.setMessage(PlatformSuccessMessages.RPR_RESIDENT_APP_SERVICE_SUCCESS.getMessage());
                description.setCode(PlatformSuccessMessages.RPR_RESIDENT_APP_SERVICE_SUCCESS.getCode());

                eventId = EventId.RPR_402.toString();
                eventName = EventName.UPDATE.toString();
                eventType = EventType.BUSINESS.toString();
            } else {
                description.setMessage(PlatformErrorMessages.RESIDENT_APP_PDF_GENERATION_FAILED.getMessage());
                description.setCode(PlatformErrorMessages.RESIDENT_APP_PDF_GENERATION_FAILED.getCode());

                eventId = EventId.RPR_405.toString();
                eventName = EventName.EXCEPTION.toString();
                eventType = EventType.SYSTEM.toString();
            }
            /** Module-Id can be Both Success/Error code */
            String moduleId = isTransactionSuccessful ? PlatformSuccessMessages.RPR_RESIDENT_APP_SERVICE_SUCCESS.getCode()
                    : description.getCode();
            String moduleName = ModuleName.RESIDENTAPP_SERVICE.toString();
            auditLogRequestBuilder.createAuditRequestBuilder(description.getMessage(), eventId, eventName, eventType,
                    moduleId, moduleName, uin);
        }
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
                "CredentialShareServiceImpl::getDocuments()::exit");

        return byteMap;
    }

    @SuppressWarnings("unchecked")
    public byte[] createJSONFile(org.json.JSONObject credential, String individualBiometric,
            Map<String, Object> attributes) throws IOException {
        org.json.JSONObject outputJSON = new org.json.JSONObject();
        if (credential == null) {
            throw new IdentityNotFoundException(PlatformErrorMessages.RESIDENT_APP_PIS_IDENTITY_NOT_FOUND.getMessage());
        }
        // Get JSON template from MOSIP config.
        // String printTextFileJson = utilities.getPrintTextFileJson(utilities.getConfigServerFileStorageURL(),
        //         utilities.getRegistrationProcessorPrintTextFile());
        // JSONObject templateJSON = JsonUtil.objectMapperReadValue(printTextFileJson, JSONObject.class);

        // Use local JSON template to include biometrics.
        JSONObject templateJSON = utilities.getTemplate();
        Set<String> templateKeys = templateJSON.keySet();
        for (String key : templateKeys) {
            String templateValue = (String) templateJSON.get(key);
            for (String value : templateValue.split(",")) {
                Object object = credential.has(value) ? credential.get(value) : null;
                if (object instanceof ArrayList) {
                    org.json.simple.JSONArray node = new org.json.simple.JSONArray();
                    node.addAll(credential.getJSONArray(value).toList());
                    JsonValue[] jsonValues = JsonUtil.mapJsonNodeToJavaObject(JsonValue.class, node);
                    for (JsonValue jsonValue : jsonValues) {
                        if (supportedLang.contains(jsonValue.getLanguage())) {
                            outputJSON.put(value + "_" + jsonValue.getLanguage(), jsonValue);
                        }
                    }
                } else if (object instanceof LinkedHashMap) {
                    org.json.JSONObject json = credential.getJSONObject(value);
                    outputJSON.put(value, json.get(VALUE));
                } else {
                    if (key.equals("biometrics")) {
                        outputJSON.put(value, getBiometricsDataJSON(individualBiometric, attributes));
                    } else {
                        outputJSON.put(value, object);
                    }
                }
            }
        }

        return outputJSON.toString().getBytes();
    }

    /**
     * Decode biometrics data from CBEFF and return biometrics JSON object.
     *
     * @param individualBiometric
     * @param attributes
     * @return
     */
    public org.json.JSONObject getBiometricsDataJSON(String individualBiometric, Map<String, Object> attributes) {
        org.json.JSONObject biometrics = new org.json.JSONObject();
        if (individualBiometric != null) {
            CbeffToBiometricUtil util = new CbeffToBiometricUtil(cbeffutil);
            try {
                List<BIR> bIRTypeList = util.getBIRTypeList(individualBiometric);
                for (int i = 0; i < bIRTypeList.size(); i++) {
                    BDBInfo bdbInfo = bIRTypeList.get(i).getBdbInfo();
                    String type = bdbInfo.getType().get(0).value().toLowerCase();
                    List<String> subType = bdbInfo.getSubtype();
                    byte[] photoBytes = util.getPhotoByTypeAndSubType(bIRTypeList, type, subType);
                    if (photoBytes != null) {
                        String data;
                        if (type.equalsIgnoreCase(BiometricType.FACE.value())) {
                            // Convert face image from JPEG2000 to JPG and encode with base64.
                            // Assume that the face image is in JPEG2000 format.
                            data = java.util.Base64.getEncoder().encodeToString(CommonUtil.convertJP2ToJPEGBytes(extractFaceImageData(photoBytes)));
                        } else {
                            data = java.util.Base64.getEncoder().encodeToString(photoBytes);
                        }
                        if (subType.isEmpty()) {
                            String formatPrefix = null;
                            if (type.equalsIgnoreCase(BiometricType.FACE.value())) {
                                formatPrefix = "data:image/jpg;base64,";
                            } else {
                                formatPrefix = "data:binary;base64,";
                            }
                            biometrics.put(type, formatPrefix + data);
                        } else {
                            org.json.JSONObject typeList = biometrics.has(type) ? biometrics.getJSONObject(type)
                                    : new org.json.JSONObject();
                            typeList.put(String.join("_", subType).toLowerCase(), "data:binary;base64," + data);
                            if (!biometrics.has(type)) {
                                biometrics.put(type, typeList);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                logger.error("Something wrong when trying to get biometrics data", e);
            }
        }

        return biometrics;
    }

    public String getSignature(String sign, String credential) {
        String signHeader = sign.split("\\.")[0];
        String signData = sign.split("\\.")[2];
        String signature = signHeader + "." + credential + "." + signData;
        return signature;
    }

    /**
     * Gets the artifacts.
     *
     * @param idJsonString the id json string
     * @param attribute    the attribute
     * @return the artifacts
     * @throws IOException    Signals that an I/O exception has occurred.
     * @throws ParseException
     */
    @SuppressWarnings("unchecked")
    public void setTemplateAttributes(String jsonString, Map<String, Object> attribute)
            throws IOException, ParseException {
        try {
            JSONObject demographicIdentity = JsonUtil.objectMapperReadValue(jsonString, JSONObject.class);
            if (demographicIdentity == null)
                throw new IdentityNotFoundException(PlatformErrorMessages.RESIDENT_APP_PIS_IDENTITY_NOT_FOUND.getMessage());

            String mapperJsonString = utilities.getIdentityMappingJson(utilities.getConfigServerFileStorageURL(),
                    utilities.getGetRegProcessorIdentityJson());
            JSONObject mapperJson = JsonUtil.objectMapperReadValue(mapperJsonString, JSONObject.class);
            JSONObject mapperIdentity = JsonUtil.getJSONObject(mapperJson,
                    utilities.getGetRegProcessorDemographicIdentity());

            List<String> mapperJsonKeys = new ArrayList<>(mapperIdentity.keySet());
            for (String key : mapperJsonKeys) {
                LinkedHashMap<String, String> jsonObject = JsonUtil.getJSONValue(mapperIdentity, key);
                Object obj = null;
                String values = jsonObject.get(VALUE);
                for (String value : values.split(",")) {
                    // Object object = demographicIdentity.get(value);
                    Object object = demographicIdentity.get(value);
                    if (object != null) {
                        try {
                            obj = new JSONParser().parse(object.toString());
                        } catch (Exception e) {
                            obj = object;
                        }

                        if (obj instanceof JSONArray) {
                            // JSONArray node = JsonUtil.getJSONArray(demographicIdentity, value);
                            JsonValue[] jsonValues = JsonUtil.mapJsonNodeToJavaObject(JsonValue.class, (JSONArray) obj);
                            for (JsonValue jsonValue : jsonValues) {
                                /*
                                 * if (jsonValue.getLanguage().equals(primaryLang)) attribute.put(value + "_" +
                                 * primaryLang, jsonValue.getValue()); if
                                 * (jsonValue.getLanguage().equals(secondaryLang)) attribute.put(value + "_" +
                                 * secondaryLang, jsonValue.getValue());
                                 */
                                if (supportedLang.contains(jsonValue.getLanguage()))
                                    attribute.put(value + "_" + jsonValue.getLanguage(), jsonValue.getValue());

                            }

                        } else if (object instanceof JSONObject) {
                            JSONObject json = (JSONObject) object;
                            attribute.put(value, (String) json.get(VALUE));
                        } else {
                            attribute.put(value, String.valueOf(object));
                        }
                    }

                }
            }

        } catch (JsonParseException | JsonMappingException e) {
            logger.error("Error while parsing Json file", e);
            throw new ParsingException(PlatformErrorMessages.RESIDENT_APP_RGS_JSON_PARSING_EXCEPTION.getMessage(), e);
        }
    }

    @SuppressWarnings("unused")
    public byte[] extractFaceImageData(byte[] decodedBioValue) {

        try (DataInputStream din = new DataInputStream(new ByteArrayInputStream(decodedBioValue))) {

            byte[] format = new byte[4];
            din.read(format, 0, 4);
            byte[] version = new byte[4];
            din.read(version, 0, 4);
            int recordLength = din.readInt();
            short numberofRepresentionRecord = din.readShort();
            byte certificationFlag = din.readByte();
            byte[] temporalSequence = new byte[2];
            din.read(temporalSequence, 0, 2);
            int representationLength = din.readInt();
            byte[] representationData = new byte[representationLength - 4];
            din.read(representationData, 0, representationData.length);
            try (DataInputStream rdin = new DataInputStream(new ByteArrayInputStream(representationData))) {
                byte[] captureDetails = new byte[14];
                rdin.read(captureDetails, 0, 14);
                byte noOfQualityBlocks = rdin.readByte();
                if (noOfQualityBlocks > 0) {
                    byte[] qualityBlocks = new byte[noOfQualityBlocks * 5];
                    rdin.read(qualityBlocks, 0, qualityBlocks.length);
                }
                short noOfLandmarkPoints = rdin.readShort();
                byte[] facialInformation = new byte[15];
                rdin.read(facialInformation, 0, 15);
                if (noOfLandmarkPoints > 0) {
                    byte[] landmarkPoints = new byte[noOfLandmarkPoints * 8];
                    rdin.read(landmarkPoints, 0, landmarkPoints.length);
                }
                byte faceType = rdin.readByte();
                byte imageDataType = rdin.readByte();
                byte[] otherImageInformation = new byte[9];
                rdin.read(otherImageInformation, 0, otherImageInformation.length);
                int lengthOfImageData = rdin.readInt();

                byte[] image = new byte[lengthOfImageData];
                rdin.read(image, 0, lengthOfImageData);

                return image;
            }
        } catch (Exception ex) {
            throw new DocumentGeneratorException(DocumentGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorCode(),
                    ex.getMessage() + ExceptionUtils.getStackTrace(ex));
        }
    }

    public String getCredentialSubject(String credential) {
        org.json.JSONObject jsonObject = new org.json.JSONObject(credential);
        String credentialSubject = jsonObject.get("credentialSubject").toString();
        return credentialSubject;
    }

    /**
     * Create datashare and update printing status via websub.
     * Should be call at the end of the event handler section.
     *
     * @param requestId
     * @param data
     * @param credentialType
     * @throws DataShareException
     * @throws ApiNotAccessibleException
     * @throws IOException
     * @throws Exception
     */
    public void statusUpdate(String requestId, byte[] data, String credentialType)
            throws DataShareException, ApiNotAccessibleException, IOException, Exception {
        DataShare dataShare = null;
        dataShare = dataShareUtil.getDataShare(data, policyId, partnerId);
        CredentialStatusEvent creEvent = new CredentialStatusEvent();
        LocalDateTime currentDtime = DateUtils.getUTCCurrentDateTime();
        StatusEvent sEvent = new StatusEvent();
        sEvent.setId(UUID.randomUUID().toString());
        sEvent.setRequestId(requestId);
        sEvent.setStatus("printing");
        sEvent.setUrl(dataShare.getUrl());
        sEvent.setTimestamp(Timestamp.valueOf(currentDtime).toString());
        creEvent.setPublishedOn(new DateTime().toString());
        creEvent.setPublisher("PRINT_SERVICE");
        creEvent.setTopic(topic);
        creEvent.setEvent(sEvent);
        webSubSubscriptionHelper.publish(topic, creEvent);
    }

    /**
     * Decrypt protected (encrypted) attributes.
     *
     * @param data
     * @param encryptionPin
     * @param credential
     * @return
     * @throws ParseException
     */
    public org.json.JSONObject decryptAttribute(org.json.JSONObject data, String encryptionPin, String credential)
            throws ParseException {

        // org.json.JSONObject jsonObj = new org.json.JSONObject(credential);
        JSONParser parser = new JSONParser(); // this needs the "json-simple" library
        Object obj = parser.parse(credential);
        JSONObject jsonObj = (org.json.simple.JSONObject) obj;

        JSONArray jsonArray = (JSONArray) jsonObj.get("protectedAttributes");
        if (jsonArray != null) {
            for (Object str : jsonArray) {

                CryptoWithPinRequestDto cryptoWithPinRequestDto = new CryptoWithPinRequestDto();
                CryptoWithPinResponseDto cryptoWithPinResponseDto = new CryptoWithPinResponseDto();

                cryptoWithPinRequestDto.setUserPin(encryptionPin);
                cryptoWithPinRequestDto.setData(data.getString(str.toString()));
                try {
                    cryptoWithPinResponseDto = cryptoUtil.decryptWithPin(cryptoWithPinRequestDto);
                } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                        | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                    logger.error("Error while decrypting the data", e);
                    throw new CryptoManagerException(PlatformErrorMessages.RESIDENT_APP_INVALID_KEY_EXCEPTION.getCode(),
                            PlatformErrorMessages.RESIDENT_APP_INVALID_KEY_EXCEPTION.getMessage(), e);
                }
                data.put((String) str, cryptoWithPinResponseDto.getData());

            }
        }

        return data;
    }

}
