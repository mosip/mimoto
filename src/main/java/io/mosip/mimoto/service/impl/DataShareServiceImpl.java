package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.util.RestApiClient;
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

    @Value("public.url")
    String publicHostUrl;

    @Value("mosip.data.share.url")
    String dataShareUrl;

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
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = restApiClient.postApi(dataShareUrl, MediaType.MULTIPART_FORM_DATA, requestEntity, DataShareResponseWrapperDTO.class);
        URL dataShareUrl = new URL(dataShareResponseWrapperDTO.getDataShare().getUrl());
//        return publicHostUrl + dataShareUrl.getPath();
        return "https://api-internal.dev.mosip.net" + dataShareUrl.getPath();
    }

}
