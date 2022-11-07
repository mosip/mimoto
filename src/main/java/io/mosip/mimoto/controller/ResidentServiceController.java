package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.mimoto.AidStatusRequestDTO;
import io.mosip.mimoto.dto.mimoto.IndividualIdOtpRequestDTO;
import io.mosip.mimoto.dto.resident.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.core.http.RequestWrapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.AppOTPRequestDTO;
import io.mosip.mimoto.dto.mimoto.AppVIDGenerateRequestDTO;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.DateUtils;
import io.mosip.mimoto.util.LoggerUtil;

@RestController
public class ResidentServiceController {

    private final Logger logger = LoggerUtil.getLogger(ResidentServiceController.class);

    @Autowired
    public RestClientService<Object> restClientService;

    @Autowired
    Environment env;

    /**
     * Request a new OTP for OTP required API.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/otp")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> otpRequest(@RequestBody AppOTPRequestDTO requestDTO) throws Exception {
        OTPRequestDTO mosipOTPRequestPayload = new OTPRequestDTO();
        mosipOTPRequestPayload.setVersion("1.0");
        mosipOTPRequestPayload.setId("mosip.identity.otp.internal");
        mosipOTPRequestPayload.setIndividualId(requestDTO.getIndividualId());
        mosipOTPRequestPayload.setIndividualIdType(requestDTO.getIndividualIdType());
        mosipOTPRequestPayload.setOtpChannel(requestDTO.getOtpChannel());
        mosipOTPRequestPayload.setRequestTime(DateUtils.getRequestTimeString());
        mosipOTPRequestPayload.setTransactionID(requestDTO.getTransactionID());

        ResponseWrapper<CredentialRequestResponseDTO> responseWrapper = (ResponseWrapper<CredentialRequestResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_OTP, "", "", mosipOTPRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Generate a new VID number using an UIN number.
     *
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/vid")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> vidGenerate(@RequestBody AppVIDGenerateRequestDTO requestDTO) throws Exception {
        VIDGenerateRequestDTO vidRequestDTO = new VIDGenerateRequestDTO();
        RequestWrapper<VIDGenerateRequestDTO> mosipVIDRequestPayload = new RequestWrapper<>();

        vidRequestDTO.setIndividualId(requestDTO.getIndividualId());
        vidRequestDTO.setIndividualIdType(requestDTO.getIndividualIdType());
        vidRequestDTO.setVidType(requestDTO.getVidType());
        vidRequestDTO.setOtp(requestDTO.getOtp());
        vidRequestDTO.setTransactionID(requestDTO.getTransactionID());
        mosipVIDRequestPayload.setId("mosip.resident.vid");
        mosipVIDRequestPayload.setVersion("v1");
        mosipVIDRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipVIDRequestPayload.setRequest(vidRequestDTO);

        ResponseWrapper<VIDGeneratorResponseDTO> responseWrapper = (ResponseWrapper<VIDGeneratorResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_VID, "", "", mosipVIDRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Request auth lock
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/auth/lock")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> authLock(@RequestBody AuthLockRequestDTO requestDTO) throws Exception {
        RequestWrapper<AuthLockRequestDTO> mosipAuthLockRequestPayload = new RequestWrapper<>();
        mosipAuthLockRequestPayload.setId("mosip.resident.authlock");
        mosipAuthLockRequestPayload.setVersion("v1");
        mosipAuthLockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthLockRequestPayload.setRequest(requestDTO);

        ResponseWrapper<AuthLockUnlockResponseDTO> responseWrapper = (ResponseWrapper<AuthLockUnlockResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AUTH_LOCK, "", "", mosipAuthLockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * Request auth unlock
     * @param requestDTO
     * @return
     * @throws Exception
     */
    @PostMapping("/req/auth/unlock")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> authUnlock(@RequestBody AuthUnlockRequestDTO requestDTO) throws Exception {
        RequestWrapper<AuthUnlockRequestDTO> mosipAuthUnlockRequestPayload = new RequestWrapper<>();
        mosipAuthUnlockRequestPayload.setId("mosip.resident.authunlock");
        mosipAuthUnlockRequestPayload.setVersion("v1");
        mosipAuthUnlockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthUnlockRequestPayload.setRequest(requestDTO);

        ResponseWrapper<AuthLockUnlockResponseDTO> responseWrapper = (ResponseWrapper<AuthLockUnlockResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AUTH_UNLOCK, "", "", mosipAuthUnlockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @PostMapping("/req/individualId/otp")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> individualIdOtpRequest(@RequestBody IndividualIdOtpRequestDTO requestDTO) throws Exception {
        IndividualIdOTPRequestDTO mosipOTPRequestPayload = new IndividualIdOTPRequestDTO();
        mosipOTPRequestPayload.setId("mosip.identity.otp.internal");
        mosipOTPRequestPayload.setVersion("1.0");
        mosipOTPRequestPayload.setRequestTime(DateUtils.getRequestTimeString());
        mosipOTPRequestPayload.setAid(requestDTO.getAid());
        mosipOTPRequestPayload.setOtpChannel(requestDTO.getOtpChannel());
        mosipOTPRequestPayload.setTransactionID(requestDTO.getTransactionID());

        OTPResponseDTO responseWrapper = (OTPResponseDTO) restClientService
                .postApi(ApiName.RESIDENT_INDIVIDUALID_OTP, "", "", mosipOTPRequestPayload, OTPResponseDTO.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @PostMapping("/aid/get-individual-id")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> aidGetIndividualId(@RequestBody AidStatusRequestDTO requestDTO) throws Exception {
        RequestWrapper<AidStatusRequestDTO> mosipAuthLockRequestPayload = new RequestWrapper<>();
        mosipAuthLockRequestPayload.setId("mosip.resident.checkstatus");
        mosipAuthLockRequestPayload.setVersion("v1");
        mosipAuthLockRequestPayload.setRequesttime(DateUtils.getRequestTimeString());
        mosipAuthLockRequestPayload.setRequest(requestDTO);

        ResponseWrapper<AidStatusResponseDTO> responseWrapper = (ResponseWrapper<AidStatusResponseDTO>) restClientService
                .postApi(ApiName.RESIDENT_AID_GET_INDIVIDUALID, "", "", mosipAuthLockRequestPayload, ResponseWrapper.class, MediaType.APPLICATION_JSON);

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

}
