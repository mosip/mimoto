package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.LoggerFileConstant;
import io.mosip.mimoto.constant.MappingJsonConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IdResponseDTO;
import io.mosip.mimoto.exception.ApisResourceAccessException;
import io.mosip.mimoto.exception.ExceptionUtils;
import io.mosip.mimoto.exception.IdRepoAppException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import lombok.Data;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import static io.mosip.mimoto.constant.LoggerFileConstant.DELIMITER;
import static io.mosip.mimoto.controller.IdpController.getErrorResponse;

@Component
@Data
public class Utilities {
    private ClassLoader classLoader = Utilities.class.getClassLoader();

    public ObjectMapper objectMapper = new ObjectMapper();

    @Value("${credential.template}")
    private String defaultTemplate;

    @Value("${credential.data.path}")
    private String dataPath;

    // Sample decrypted VC
    private String SAMPLE_VCD = "%s_VCD.json";

    // Sample VC websub event
    private String SAMPLE_EVENT = "%s_EVENT.json";

    private Logger logger = LoggerUtil.getLogger(Utilities.class);

    /**
     * The Constant FILE_SEPARATOR.
     */
    public static final String FILE_SEPARATOR = "\\";

    @Autowired
    private ObjectMapper objMapper;

    @Autowired
    private RestApiClient restApiClient;

    /**
     * The rest client service.
     */
    @Autowired
    private RestClientService<Object> restClientService;

    /**
     * The config server file storage URL.
     */
    @Value("${config.server.file.storage.uri}")
    private String configServerFileStorageURL;

    /**
     * The get reg processor identity json.
     */
    @Value("${registration.processor.identityjson}")
    private String getRegProcessorIdentityJson;

    /**
     * The get reg processor demographic identity.
     */
    @Value("${registration.processor.demographic.identity}")
    private String getRegProcessorDemographicIdentity;

    /**
     * The registration processor abis json.
     */
    @Value("${registration.processor.print.textfile}")
    private String registrationProcessorPrintTextFile;

    /**
     * The get reg issuers config json.
     */
    @Value("${mosip.openid.issuers}")
    private String getIssuersConfigJson;

    @Value("${mosip.openid.htmlTemplate}")
    private String getCredentialSupportedHtml;

    private String mappingJsonString = null;

    private String identityMappingJsonString = null;

    private String printTextFileJsonString = null;

    private String issuersConfigJsonString = null;

    private String credentialTemplateHtmlString = null;
//    uncomment for running mimoto Locally to populate the issuers json
//    public Utilities(@Value("classpath:mimoto-issuers-config.json") Resource resource,
//                     @Value("classpath:/templates/CredentialTemplate.html") Resource credentialTemplateResource) throws IOException{
//
//        issuersConfigJsonString = (Files.readString(resource.getFile().toPath()));
//        credentialTemplateHtmlString = (Files.readString(credentialTemplateResource.getFile().toPath()));
//    }

    public JSONObject getTemplate() throws JsonParseException, JsonMappingException, IOException {
        return objectMapper.readValue(classLoader.getResourceAsStream(defaultTemplate), JSONObject.class);
    }

    public JsonNode getEvent(String requestId, String individualId) throws JsonParseException, JsonMappingException, IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.EVENT_JSON_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public JsonNode getVC(String requestId) throws JsonParseException, JsonMappingException, IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_JSON_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public JsonNode getRequestVC(String requestId) throws JsonParseException, JsonMappingException, IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public JsonNode getDecryptedVC(String requestId) throws JsonParseException, JsonMappingException, IOException {
        Path resourcePath = Path.of(dataPath, String.format(CredentialShareServiceImpl.CARD_JSON_FILE_NAME, requestId));
        if (Files.exists(resourcePath)) {
            return objectMapper.readValue(resourcePath.toFile(), JsonNode.class);
        }
        return null;
    }

    public void removeCacheData(String requestId) throws IOException {
        List<Path> filePathList = new ArrayList<Path>();
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.EVENT_JSON_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.VC_JSON_FILE_NAME, requestId)));
        filePathList.add(Path.of(dataPath, String.format(CredentialShareServiceImpl.CARD_JSON_FILE_NAME, requestId)));
        for (Path filePath : filePathList) {
            if (Files.exists(filePath)) {
                try {
                    Files.delete(filePath);
                } catch (Exception e) {
                    logger.error("Cannot delete file: " + filePath, e);
                }
            }
        }
    }

    /**
     * Gets the json.
     *
     * @param configServerFileStorageURL the config server file storage URL
     * @param uri                        the uri
     * @return the json
     */
    public String getJson(String configServerFileStorageURL, String uri) {
        String json = null;
        try {
            json = restApiClient.getApi(URI.create(configServerFileStorageURL + uri), String.class);
        } catch (Exception e) {
            logger.error(ExceptionUtils.getStackTrace(e));
        }
        return json;
    }

    public String getPrintTextFileJson(String configServerFileStorageURL, String uri) {
        printTextFileJsonString = (printTextFileJsonString != null && !printTextFileJsonString.isEmpty()) ?
                printTextFileJsonString : getJson(configServerFileStorageURL, uri);
        return printTextFileJsonString;
    }

    public String getIdentityMappingJson(String configServerFileStorageURL, String uri) {
        identityMappingJsonString = (identityMappingJsonString != null && !identityMappingJsonString.isEmpty()) ?
                identityMappingJsonString : getJson(configServerFileStorageURL, uri);
        return identityMappingJsonString;
    }

    /**
     * retrieving identity json ffrom id repo by UIN.
     *
     * @param uin the uin
     * @return the JSON object
     * @throws ApisResourceAccessException the apis resource access exception
     * @throws IdRepoAppException          the id repo app exception
     * @throws IOException                 Signals that an I/O exception has
     *                                     occurred.
     */
    @SuppressWarnings("unchecked")
    public JSONObject retrieveIdrepoJson(String uin)
            throws ApisResourceAccessException, IdRepoAppException, IOException {

        if (uin != null) {
            logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                    "Utilities::retrieveIdrepoJson()::entry");
            List<String> pathSegments = new ArrayList<>();
            pathSegments.add(uin);
            ResponseWrapper<IdResponseDTO> idResponseDto;

            idResponseDto = (ResponseWrapper<IdResponseDTO>) restClientService.getApi(ApiName.IDREPOGETIDBYUIN, pathSegments, "", "",
                    ResponseWrapper.class);
            if (idResponseDto == null) {
                logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                        "Utilities::retrieveIdrepoJson()::exit idResponseDto is null");
                return null;
            }
            if (!idResponseDto.getErrors().isEmpty()) {
                List<ErrorDTO> error = idResponseDto.getErrors();
                logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                        "Utilities::retrieveIdrepoJson():: error with error message " + error.get(0).getErrorMessage());
                throw new IdRepoAppException(error.get(0).getErrorMessage());
            }
            String response = objMapper.writeValueAsString(idResponseDto.getResponse().getIdentity());
            logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                    "Utilities::retrieveIdrepoJson():: IDREPOGETIDBYUIN GET service call ended Successfully");
            try {
                return (JSONObject) new JSONParser().parse(response);
            } catch (org.json.simple.parser.ParseException e) {
                logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                        ExceptionUtils.getStackTrace(e));
                throw new IdRepoAppException("Error while parsing string to JSONObject", e);
            }

        }
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                "Utilities::retrieveIdrepoJson()::exit UIN is null");
        return null;
    }

    /**
     * Gets registration processor mapping json from config and maps to
     * RegistrationProcessorIdentity java class.
     *
     * @return the registration processor identity json
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public JSONObject getRegistrationProcessorMappingJson() throws IOException {
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), "",
                "Utilities::getRegistrationProcessorMappingJson()::entry");

        mappingJsonString = (mappingJsonString != null && !mappingJsonString.isEmpty()) ?
                mappingJsonString : getJson(configServerFileStorageURL, getRegProcessorIdentityJson);
        ObjectMapper mapIdentityJsonStringToObject = new ObjectMapper();
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), "",
                "Utilities::getRegistrationProcessorMappingJson()::exit");
        return JsonUtil.getJSONObject(mapIdentityJsonStringToObject.readValue(mappingJsonString, JSONObject.class), MappingJsonConstants.IDENTITY);

    }

    public String getMappingJsonValue(String key) throws IOException {
        JSONObject jsonObject = getRegistrationProcessorMappingJson();
        Object obj = jsonObject.get(key);
        if (obj instanceof LinkedHashMap) {
            LinkedHashMap hm = (LinkedHashMap) obj;
            return hm.get("value") != null ? hm.get("value").toString() : null;
        }
        return jsonObject.get(key) != null ? jsonObject.get(key).toString() : null;
    }

    public String getIssuersConfigJsonValue() throws IOException {
        return  (issuersConfigJsonString != null && !issuersConfigJsonString.isEmpty()) ?
                issuersConfigJsonString : getJson(configServerFileStorageURL, getIssuersConfigJson);
    }

    public static ResponseWrapper<Object> handleExceptionWithErrorCode(Exception exception) {
        String errorMessage = exception.getMessage();
        String errorCode = PlatformErrorMessages.MIMOTO_IDP_GENERIC_EXCEPTION.getCode();

        if(errorMessage.contains(DELIMITER)){
            String[] errorSections = errorMessage.split(DELIMITER);
            errorCode = errorSections[0];
            errorMessage = errorSections[1];
        }
        return getErrorResponse(errorCode, errorMessage);
    }

    public String getCredentialSupportedTemplateString() throws IOException{
        return (credentialTemplateHtmlString != null && !credentialTemplateHtmlString.isEmpty()) ?
                credentialTemplateHtmlString : getJson(configServerFileStorageURL, getCredentialSupportedHtml);
    }


    /**
     * retrieve UIN from IDRepo by registration id.
     *
     * @param regId the reg id
     * @return the JSON object
     * @throws ApisResourceAccessException the apis resource access exception
     * @throws IdRepoAppException          the id repo app exception
     * @throws IOException                 Signals that an I/O exception has
     *                                     occurred.
     */
    @SuppressWarnings("unchecked")
    public JSONObject retrieveUIN(String regId) throws ApisResourceAccessException, IdRepoAppException, IOException {
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                regId, "Utilities::retrieveUIN()::entry");

        if (regId != null) {
            List<String> pathSegments = new ArrayList<>();
            pathSegments.add(regId);
            ResponseWrapper<IdResponseDTO> idResponseDto;
            logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                    regId, "Utilities::retrieveUIN():: RETRIEVEIDENTITYFROMRID GET service call Started");

            idResponseDto = (ResponseWrapper<IdResponseDTO>) restClientService.getApi(ApiName.RETRIEVEIDENTITYFROMRID, pathSegments, "",
                    "", ResponseWrapper.class);
            logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                    "Utilities::retrieveUIN():: RETRIEVEIDENTITYFROMRID GET service call ended successfully");

            if (!idResponseDto.getErrors().isEmpty()) {
                logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
                        regId,
                        "Utilities::retrieveUIN():: error with error message "
                                + PlatformErrorMessages.MIMOTO_PVM_INVALID_UIN.getMessage() + " "
                                + idResponseDto.getErrors().toString());
                throw new IdRepoAppException(
                        PlatformErrorMessages.MIMOTO_PVM_INVALID_UIN.getMessage() + idResponseDto.getErrors().toString());
            }
            String response = objMapper.writeValueAsString(idResponseDto.getResponse().getIdentity());
            try {
                return (JSONObject) new JSONParser().parse(response);
            } catch (org.json.simple.parser.ParseException e) {
                logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.UIN.toString(), "",
                        ExceptionUtils.getStackTrace(e));
                throw new IdRepoAppException("Error while parsing string to JSONObject", e);
            }

        }
        logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
                "Utilities::retrieveUIN()::exit regId is null");

        return null;
    }
}
