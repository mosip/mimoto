package io.mosip.mimoto.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.Gson;

import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.util.*;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.websub.api.annotation.PreAuthenticateContentAndVerifyIntent;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.AppCredentialRequestDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadRequestDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDownloadResponseDTO;
import io.mosip.mimoto.dto.mimoto.GenericResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestResponseDTO;
import io.mosip.mimoto.dto.resident.CredentialRequestStatusResponseDTO;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;

import javax.validation.Valid;

@RestController
@RequestMapping(value = "/credentialshare")
public class CredentialShareController {

    private Logger logger = LoggerUtil.getLogger(CredentialShareController.class);

    @Autowired
    private CredentialShareServiceImpl credentialShareService;

    @Autowired
    public RestClientService<Object> restClientService;

    @Autowired
    Environment env;

    @Value("${mosip.event.topic}")
    private String topic;

    @Value("${mosip.partner.encryption.key}")
    private String partnerEncryptionKey;

    @Value("${mosip.partner.id}")
    private String partnerId;

    @Autowired
    public CryptoCoreUtil cryptoCoreUtil;

    @Autowired
    RequestValidator requestValidator;

    private Gson gson = new Gson();

    @Autowired
    private Utilities utilities;

    /**
     * Websub callback for Verifiable Credential share.
     *
     * @param eventModel
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/callback/notify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthenticateContentAndVerifyIntent(secret = "${mosip.event.secret}", callback = "/v1/mimoto/credentialshare/callback/notify", topic = "${mosip.event.topic}")
    public ResponseEntity<GenericResponseDTO> handleSubscribeEvent(@RequestBody EventModel eventModel)
            throws Exception {
        logger.info("Received websub event:: transaction id = " + eventModel.getEvent().getTransactionId());
        logger.debug("Received websub event:: " + JsonUtils.javaObjectToJsonString(eventModel));
        GenericResponseDTO responseDTO = new GenericResponseDTO();
        Path vcRequestIdPath = Path.of(
            utilities.getDataPath(),
            String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, eventModel.getEvent().getTransactionId())
        );
        // Only process event if request id file exists in the storange.
        if (vcRequestIdPath.toFile().exists()) {
            boolean documentGenerated = credentialShareService.generateDocuments(eventModel);
            logger.info("Credential share process status: {} for event id: {}", documentGenerated, eventModel.getEvent().getId());
        } else {
            logger.warn("Event transaction id could not found in the storage, skipping...");
        }
        responseDTO.setStatus("OK");
        responseDTO.setMessage("Successfully issued.");
        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

    /**
     * Request to publish a VC: print, share or download.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/request", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> request(@RequestBody AppCredentialRequestDTO requestDTO)
            throws Exception {

        if (StringUtils.isEmpty(requestDTO.getIndividualId())) {
            logger.error("Received empty individual id for transaction id - " + requestDTO.getTransactionID());
        }

        // Call mosip resident service to issue a new credential
        RequestWrapper<CredentialRequestDTO> mosipCredentialRequestPayload = new RequestWrapper<CredentialRequestDTO>();

        CredentialRequestDTO credentialReqDTO = new CredentialRequestDTO();
        credentialReqDTO.setEncryptionKey(partnerEncryptionKey);
        credentialReqDTO.setIssuer(partnerId);
        credentialReqDTO.setIndividualId(requestDTO.getIndividualId());
        credentialReqDTO.setOtp(requestDTO.getOtp());
        credentialReqDTO.setTransactionID(requestDTO.getTransactionID());
        credentialReqDTO.setCredentialType(requestDTO.getCredentialType());
        credentialReqDTO.setUser(requestDTO.getUser());

        mosipCredentialRequestPayload.setId("mosip.resident.vid");
        mosipCredentialRequestPayload.setVersion("v1");
        mosipCredentialRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipCredentialRequestPayload.setRequest(credentialReqDTO);

        CredentialRequestResponseDTO response = (CredentialRequestResponseDTO)restClientService
                .postApi(ApiName.RESIDENT_CREDENTIAL_REQUEST, "", "", mosipCredentialRequestPayload,
                CredentialRequestResponseDTO.class, MediaType.APPLICATION_JSON);

        // Create request id file for later event.
        if (response.getErrors() == null || response.getErrors().isEmpty()) {
            Path vcRequestIdPath = Path.of(
                utilities.getDataPath(),
                String.format(CredentialShareServiceImpl.VC_REQUEST_FILE_NAME, response.getResponse().getRequestId())
            );
            Files.write(vcRequestIdPath, gson.toJson(response).getBytes());
        }

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * The VC request status.
     *
     * @param requestId
     * @return
     * @throws Exception
     */
    @GetMapping(path = "/request/status/{requestId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> requestStatus(@PathVariable("requestId") String requestId)
            throws Exception {

        List<String> pathSegment = new ArrayList<String>();
        pathSegment.add(requestId);
        ResponseWrapper<CredentialRequestStatusResponseDTO> responseWrapper = (ResponseWrapper<CredentialRequestStatusResponseDTO>) restClientService
                .getApi(ApiName.RESIDENT_CREDENTIAL_REQUEST_STATUS, pathSegment, "", "", ResponseWrapper.class);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Download a received and decrypted VC.
     * Original VC data and decrypted identity will be combined in a single response
     * to display on the frontend.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/download", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CredentialDownloadResponseDTO> download(@Valid @RequestBody CredentialDownloadRequestDTO requestDTO, BindingResult result)
            throws Exception {
        try {
            requestValidator.validateInputRequest(result);
            JsonNode decryptedCredentialJSON = utilities.getDecryptedVC(requestDTO.getRequestId());
            JsonNode requestedCredentialJSON = utilities.getRequestVC(requestDTO.getRequestId());
            JsonNode credentialJSON = utilities.getVC(requestDTO.getRequestId());

            // Combine original encrypted verifiable credential and decrypted
            if (decryptedCredentialJSON != null && credentialJSON != null) {
                requestValidator.validateCredentialDownloadRequest(requestDTO, requestedCredentialJSON);
                CredentialDownloadResponseDTO credentialDownloadBody = new CredentialDownloadResponseDTO();
                credentialDownloadBody.setCredential(decryptedCredentialJSON);
                credentialDownloadBody.setVerifiableCredential(credentialJSON);

                // Remove cached data.
                utilities.removeCacheData(requestDTO.getRequestId());
                return ResponseEntity.ok().body(credentialDownloadBody);
            }

            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (IOException exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
