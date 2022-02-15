package io.mosip.residentapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.residentapp.constant.ApiName;
import io.mosip.residentapp.core.http.RequestWrapper;
import io.mosip.residentapp.core.http.ResponseWrapper;
import io.mosip.residentapp.dto.AppOTPRequestDTO;
import io.mosip.residentapp.dto.AppVIDGenerateRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.AuthLockRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.AuthLockUnlockResponseDTO;
import io.mosip.residentapp.dto.mosip.resident.AuthUnlockRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.CredentialRequestResponseDTO;
import io.mosip.residentapp.dto.mosip.resident.OTPRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.VIDGenerateRequestDTO;
import io.mosip.residentapp.dto.mosip.resident.VIDGeneratorResponseDTO;
import io.mosip.residentapp.service.RestClientService;
import io.mosip.residentapp.util.DateUtils;
import io.mosip.residentapp.util.LoggerUtil;

@SpringBootApplication
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

}
