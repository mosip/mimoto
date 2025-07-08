package io.mosip.mimoto.model;

import lombok.Data;

@Data
public class WalletMetadata {
    private String encryptionAlgo;
    private String encryptionType;
    private String name;
    private PasscodeControl passcodeControl;
    private WalletStatus status = null;
}
