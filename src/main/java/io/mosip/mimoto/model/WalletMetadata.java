package io.mosip.mimoto.model;

import io.mosip.mimoto.model.WalletStatus;
import lombok.Data;

@Data
public class WalletMetadata {
    private String encryptionAlgo;
    private String encryptionType;
    private String name;
    private PasscodeMetadata passcodeMetadata;
    private WalletStatus status = null;
}
