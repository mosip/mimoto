package io.mosip.residentapp.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.websub.api.annotation.PreAuthenticateContentAndVerifyIntent;
import io.mosip.residentapp.constant.ApiName;
import io.mosip.residentapp.core.http.RequestWrapper;
import io.mosip.residentapp.core.http.ResponseWrapper;
import io.mosip.residentapp.dto.AppCredentialRequestDTO;
import io.mosip.residentapp.dto.CredentialDownloadRequestDTO;
import io.mosip.residentapp.dto.CredentialDownloadResponseDTO;
import io.mosip.residentapp.dto.GenericResponseDTO;
import io.mosip.residentapp.dto.mosip.resident.CredentialRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.CredentialRequestResponseDTO;
import io.mosip.residentapp.dto.mosip.resident.CredentialRequestStatusResponseDTO;
import io.mosip.residentapp.model.EventModel;
import io.mosip.residentapp.service.RestClientService;
import io.mosip.residentapp.service.impl.CredentialShareServiceImpl;
import io.mosip.residentapp.util.CryptoCoreUtil;
import io.mosip.residentapp.util.DateUtils;
import io.mosip.residentapp.util.LoggerUtil;
import io.mosip.residentapp.util.Utilities;

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
    private Utilities utilities;

    /**
     * Websub callback for Verifiable Credential share.
     *
     * @param eventModel
     * @return
     * @throws Exception
     */
    @PostMapping(path = "/callback/notify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthenticateContentAndVerifyIntent(secret = "${mosip.event.secret}", callback = "/v1/resident/credentialshare/callback/notify", topic = "${mosip.event.topic}")
    public ResponseEntity<GenericResponseDTO> handleSubscribeEvent(@RequestBody EventModel eventModel)
            throws Exception {
        logger.info("Received event:: transaction id = " + eventModel.getEvent().getTransactionId());
        boolean documentGenerated = credentialShareService.generateDocuments(eventModel);
        logger.info("Credential share process status: {} for event id: {}", documentGenerated, eventModel.getEvent().getId());
        GenericResponseDTO responseDTO = new GenericResponseDTO();
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
    @SuppressWarnings("unchecked")
    @PostMapping(path = "/request", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> request(@RequestBody AppCredentialRequestDTO requestDTO)
            throws Exception {
        // Call mosip resident service to issue a new credential
        RequestWrapper<CredentialRequestDTO> mosipCredentialRequestPayload = new RequestWrapper<CredentialRequestDTO>();

        CredentialRequestDTO credentialReqDTO = new CredentialRequestDTO();
        credentialReqDTO.setEncryptionKey(partnerEncryptionKey);
        credentialReqDTO.setIssuer(partnerId);
        credentialReqDTO.setIndividualId(requestDTO.getIndividualId());
        credentialReqDTO.setOtp(requestDTO.getOtp());
        credentialReqDTO.setTransactionID(requestDTO.getTransactionID());
        credentialReqDTO.setCredentialType("vercred");
        credentialReqDTO.setUser("taheer");

        mosipCredentialRequestPayload.setId("mosip.resident.vid");
        mosipCredentialRequestPayload.setVersion("v1");
        mosipCredentialRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipCredentialRequestPayload.setRequest(credentialReqDTO);

        ResponseWrapper<CredentialRequestResponseDTO> responseWrapper = (ResponseWrapper<CredentialRequestResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_CREDENTIAL_REQUEST, "", "", mosipCredentialRequestPayload,
                        ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
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
    public ResponseEntity<Object> requestStatus(@PathVariable String requestId)
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
    public ResponseEntity<CredentialDownloadResponseDTO> download(@RequestBody CredentialDownloadRequestDTO requestDTO)
            throws Exception {
        try {

            JsonNode decryptedCredentialJSON = utilities.getDecryptedVC(requestDTO.getRequestId(),
                    requestDTO.getIndividualId());

            JsonNode credentialJSON = utilities.getVC(requestDTO.getRequestId(), requestDTO.getIndividualId());

            // Combine original encrypted verifiable credential and decrypted
            if (decryptedCredentialJSON != null && credentialJSON != null) {
                CredentialDownloadResponseDTO credentialDownloadBody = new CredentialDownloadResponseDTO();
                credentialDownloadBody.setCredential(decryptedCredentialJSON);
                credentialDownloadBody.setVerifiableCredential(credentialJSON);

                return ResponseEntity.ok().body(credentialDownloadBody);
            }

            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (IOException exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
