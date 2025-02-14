package io.mosip.mimoto.controller;

import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.constant.ApiName;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RequestValidator;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
@Tag(name = SwaggerLiteralConstants.IDP_NAME, description = SwaggerLiteralConstants.IDP_DESCRIPTION)
public class IdpController {
    private static final boolean USE_BEARER_TOKEN = true;

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

    @Autowired
    CredentialServiceImpl credentialService;

    @Operation(summary = SwaggerLiteralConstants.IDP_BINDING_OTP_SUMMARY, description = SwaggerLiteralConstants.IDP_BINDING_OTP_DESCRIPTION)
    @PostMapping(value = "/binding-otp", produces = MediaType.APPLICATION_JSON_VALUE)
    @SuppressWarnings("unchecked")
    public ResponseEntity<ResponseWrapper<BindingOtpResponseDto>> otpRequest(@Valid @RequestBody BindingOtpRequestDto requestDTO, BindingResult result) throws Exception {
        log.debug("Received binding-otp request : " + JsonUtils.javaObjectToJsonString(requestDTO));
        requestValidator.validateInputRequest(result);
        requestValidator.validateNotificationChannel(requestDTO.getRequest().getOtpChannels());
        ResponseWrapper<BindingOtpResponseDto> responseWrapper = new ResponseWrapper<>();
        try {
            ResponseWrapper<BindingOtpResponseDto> internalResponse = (ResponseWrapper<BindingOtpResponseDto>) restClientService.postApi(ApiName.BINDING_OTP, requestDTO, ResponseWrapper.class, USE_BEARER_TOKEN);
            if (internalResponse == null)
                throw new IdpException();
            return ResponseEntity.status(HttpStatus.OK).body(internalResponse);
        } catch (Exception e) {
            log.error("Wallet binding otp error occurred." + e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, PlatformErrorMessages.MIMOTO_OTP_BINDING_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }

    }

    @Operation(summary = SwaggerLiteralConstants.IDP_WALLET_BINDING_SUMMARY, description = SwaggerLiteralConstants.IDP_WALLET_BINDING_DESCRIPTION)
    @PostMapping(path = "/wallet-binding", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<WalletBindingResponseDto>> request(@RequestBody WalletBindingRequestDTO requestDTO)
            throws Exception {

        log.debug("Received wallet-binding request : " + JsonUtils.javaObjectToJsonString(requestDTO));
        ResponseWrapper<WalletBindingResponseDto> responseWrapper = new ResponseWrapper<WalletBindingResponseDto>();
        try {
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

            responseWrapper = joseUtil.addThumbprintAndKeyId(internalResponse);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception e) {
            log.error("Wallet binding error occured for tranaction id " + requestDTO.getRequest().getIndividualId(), e);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(e, PlatformErrorMessages.MIMOTO_WALLET_BINDING_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }

    @Operation(summary = SwaggerLiteralConstants.IDP_GET_TOKEN_SUMMARY, description = SwaggerLiteralConstants.IDP_GET_TOKEN_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = { @Content(schema = @Schema(implementation = TokenResponseDTO.class), mediaType = "application/json") }),
            @ApiResponse(responseCode = "400", content = { @Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json") }) })
    @PostMapping(value = {"/get-token/{issuer}"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getToken(@RequestParam Map<String, String> params, @PathVariable(required = true, name= "issuer") String issuer) {
        log.info("Reached the getToken Controller for Issuer " + issuer);
        ResponseWrapper<TokenResponseDTO> responseWrapper = new ResponseWrapper<>();
        try {
            TokenResponseDTO response = credentialService.getTokenResponse(params, issuer);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception ex) {
            log.error("Exception Occurred while Invoking the Token Endpoint : ", ex);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(ex, PlatformErrorMessages.MIMOTO_FETCHING_TOKEN_EXCEPTION.getCode());
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }
}
