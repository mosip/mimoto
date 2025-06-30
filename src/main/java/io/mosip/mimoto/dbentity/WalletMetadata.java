package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class WalletMetadata {

    private String encryptionAlgo;
    private String encryptionType;
    private String name;
    private long lockUntil;
    private PasscodeMetadata passcodeMetadata;

}
