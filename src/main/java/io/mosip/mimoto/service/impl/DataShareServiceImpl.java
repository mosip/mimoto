package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.OpenIdErrorMessages;
import io.mosip.mimoto.util.RestApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;

import java.net.URL;

@Service
public class DataShareServiceImpl {

    @Autowired
    RestApiClient restApiClient;

    @Value("${mosip.data.share.url}")
    String dataShareHostUrl;

    @Value("${mosip.data.share.create.url}")
    String dataShareCreateUrl;

    @Value("${mosip.data.share.create.retry.count}")
    Integer maxRetryCount;

    private final Logger logger = LoggerFactory.getLogger(DataShareServiceImpl.class);

    @Autowired
    ObjectMapper objectMapper;

    public String storeDataInDataShare(String data) throws Exception {
        ByteArrayResource contentsAsResource = new ByteArrayResource(data.getBytes()) {
            @Override
            public String getFilename() {
                return "credential_file";
            }
        };
        LinkedMultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
        map.add("file", contentsAsResource);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity = new HttpEntity<>(map, headers);
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = pushCredentialIntoDataShare(requestEntity);
        URL dataShareUrl = new URL(dataShareResponseWrapperDTO.getDataShare().getUrl());
        return dataShareHostUrl + dataShareUrl.getPath();
    }

    private DataShareResponseWrapperDTO pushCredentialIntoDataShare(HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity) throws Exception {
        int attempt =0 ;
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = null;
        while(attempt++ < maxRetryCount ){
            try {
                dataShareResponseWrapperDTO = restApiClient.postApi(dataShareCreateUrl, MediaType.MULTIPART_FORM_DATA, requestEntity, DataShareResponseWrapperDTO.class);
            } catch (Exception e) {
                logger.error(attempt + " attempt to push credential failed");
            }
        }
        if(dataShareResponseWrapperDTO == null){
            throw new InvalidCredentialResourceException(
                    OpenIdErrorMessages.REQUEST_TIMED_OUT.getErrorCode(),
                    OpenIdErrorMessages.REQUEST_TIMED_OUT.getErrorMessage());
        }
        return dataShareResponseWrapperDTO;
    }

    public  VCCredentialResponse downloadCredentialFromDataShare(PresentationRequestDTO presentationRequestDTO) throws JsonProcessingException {
        logger.info("Started the Credential Download From DataShare");
        String credentialsResourceUri = presentationRequestDTO.getResource();
        String vcCredentialResponseString = restApiClient.getApi(credentialsResourceUri, String.class);
        if (vcCredentialResponseString == null) {
            throw new InvalidCredentialResourceException(
                    OpenIdErrorMessages.SERVER_UNAVAILABLE.getErrorCode(),
                    OpenIdErrorMessages.SERVER_UNAVAILABLE.getErrorMessage());
        }
        VCCredentialResponse vcCredentialResponse = objectMapper.readValue(vcCredentialResponseString, VCCredentialResponse.class);
        if(vcCredentialResponse.getCredential() == null){
            throw new InvalidCredentialResourceException(OpenIdErrorMessages.RESOURCE_EXPIRED.getErrorMessage());
        }
        return vcCredentialResponse;
    }

}
