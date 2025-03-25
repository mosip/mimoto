package io.mosip.mimoto.config;

import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class KeyManagerConfig implements ApplicationRunner {


    @Autowired
    private KeymanagerService keymanagerService;


    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("===================== MIMOTOSERVICE ROOT KEY CHECK ========================");
        String objectType = "CSR";
        KeyPairGenerateRequestDto rootKeyRequest = new KeyPairGenerateRequestDto();
        rootKeyRequest.setApplicationId("ROOT");
        // Set the reference id to empty string, as keymanager is expecting the same for initialization
        rootKeyRequest.setReferenceId(org.apache.commons.lang3.StringUtils.EMPTY);
        keymanagerService.generateMasterKey(objectType, rootKeyRequest);
        log.info("===================== MIMOTOSERVICE MASTER KEY CHECK ========================");
        KeyPairGenerateRequestDto masterKeyRequest = new KeyPairGenerateRequestDto();
        masterKeyRequest.setApplicationId("MIMOTO");
        // Set the reference id to empty string, as keymanager is expecting the same for initialization
        masterKeyRequest.setReferenceId(org.apache.commons.lang3.StringUtils.EMPTY);
        keymanagerService.generateMasterKey(objectType, masterKeyRequest);
        log.info("===================== MIMOTO KEY SETUP COMPLETED ========================");
    }
}
