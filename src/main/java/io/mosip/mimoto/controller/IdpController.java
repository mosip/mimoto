package io.mosip.mimoto.controller;

import com.google.common.collect.Lists;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.validation.Valid;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.Utilities.handleExceptionWithErrorCode;

@RestController
public class IdpController {

    private final Logger logger = LoggerUtil.getLogger(IdpController.class);
    private static final boolean USE_BEARER_TOKEN = true;
    private static final String ID = "mosip.mimoto.idp";

    @Autowired
    private RestClientService<Object> restClientService;

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    IssuersService issuersService;

    @Autowired
    IdpService idpService;

    @Autowired
    RequestValidator requestValidator;
    @PostMapping("/binding-otp")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> otpRequest(@Valid @RequestBody BindingOtpRequestDto requestDTO, BindingResult result) throws Exception {
        logger.debug("Received binding-otp request : " + JsonUtils.javaObjectToJsonString(requestDTO));
        requestValidator.validateInputRequest(result);
        requestValidator.validateNotificationChannel(requestDTO.getRequest().getOtpChannels());

        try {
            ResponseWrapper<BindingOtpResponseDto> response = null;
            response = (ResponseWrapper<BindingOtpResponseDto>) restClientService
                    .postApi(ApiName.BINDING_OTP,
                            requestDTO, ResponseWrapper.class, USE_BEARER_TOKEN);
            if (response == null)
                throw new IdpException();

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            logger.error("Wallet binding otp error occurred.", e);
            ResponseWrapper<Object> response = getErrorResponse(PlatformErrorMessages.MIMOTO_OTP_BINDING_EXCEPTION.getCode(), e.getMessage());
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }

    }

    @PostMapping(path = "/wallet-binding", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> request(@RequestBody WalletBindingRequestDTO requestDTO)
            throws Exception {

        logger.debug("Received wallet-binding request : " + JsonUtils.javaObjectToJsonString(requestDTO));
        try {
            ResponseWrapper<WalletBindingResponseDto> response = null;
            WalletBindingInnerRequestDto innerRequestDto = new WalletBindingInnerRequestDto();
            innerRequestDto.setChallengeList(requestDTO.getRequest().getChallengeList());
            innerRequestDto.setIndividualId(requestDTO.getRequest().getIndividualId());
            innerRequestDto.setPublicKey(JoseUtil.getJwkFromPublicKey(requestDTO.getRequest().getPublicKey()));
            innerRequestDto.setAuthFactorType(requestDTO.getRequest().getAuthFactorType());
            innerRequestDto.setFormat(requestDTO.getRequest().getFormat());

            WalletBindingInternalRequestDTO req = new WalletBindingInternalRequestDTO(requestDTO.getRequestTime(), innerRequestDto);

            ResponseWrapper<WalletBindingInternalResponseDto> internalResponse = (ResponseWrapper<WalletBindingInternalResponseDto>) restClientService
                    .postApi(ApiName.WALLET_BINDING,
                            req, ResponseWrapper.class, USE_BEARER_TOKEN);

            if (internalResponse == null)
                throw new IdpException();

            response = joseUtil.addThumbprintAndKeyId(internalResponse);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            logger.error("Wallet binding error occured for tranaction id " + requestDTO.getRequest().getIndividualId(), e);
            ResponseWrapper<Object> response = getErrorResponse(PlatformErrorMessages.MIMOTO_WALLET_BINDING_EXCEPTION.getCode(), e.getMessage());
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }
    }

    @PostMapping(value = {"/get-token/{issuer}"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity getToken(@RequestParam Map<String, String> params, @PathVariable(required = false) String issuer) {
        logger.info("Reached the getToken Controller for Issuer " + issuer);
        RestTemplate restTemplate = new RestTemplate();
        try {
            IssuerDTO issuerDTO = issuersService.getIssuerConfig(issuer);
            HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO);
            TokenResponseDTO response = restTemplate.postForObject(idpService.getTokenEndpoint(issuerDTO), request, TokenResponseDTO.class);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception ex){
            logger.error("Exception Occurred while Invoking the Token Endpoint : ", ex);
            ResponseWrapper<Object> response = handleExceptionWithErrorCode(ex);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    public static ResponseWrapper<Object> getErrorResponse(String errorCode, String errorMessage) {

        List<ErrorDTO> errors = getErrors(errorCode, errorMessage);
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setResponse(null);
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());
        responseWrapper.setId(ID);
        responseWrapper.setErrors(errors);

        return responseWrapper;
    }

    public static List<ErrorDTO> getErrors(String errorCode, String errorMessage) {
        ErrorDTO errorDTO = new ErrorDTO(errorCode, errorMessage);
        return Lists.newArrayList(errorDTO);
    }
}
