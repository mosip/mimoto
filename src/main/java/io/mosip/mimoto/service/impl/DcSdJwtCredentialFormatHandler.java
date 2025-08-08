package io.mosip.mimoto.service.impl;


import io.mosip.mimoto.constant.CredentialFormat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component("dc+sd-jwt")
public class DcSdJwtCredentialFormatHandler extends VcSdJwtCredentialFormatHandler {
    @Override
    public String getSupportedFormat() {
        return CredentialFormat.DC_SD_JWT.getFormat();
    }
}