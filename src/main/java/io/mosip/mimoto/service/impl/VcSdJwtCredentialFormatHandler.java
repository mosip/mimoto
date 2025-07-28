package io.mosip.mimoto.service.impl;


import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Component
public class VcSdJwtCredentialFormatHandler extends DcSdJwtCredentialFormatHandler {
    @Override
    public String getSupportedFormat() {
        return CredentialFormat.VC_SD_JWT.getFormat();
    }
}