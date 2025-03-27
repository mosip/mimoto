package io.mosip.mimoto.dbentity;

import jakarta.persistence.Column;
import lombok.Data;
@Data
public class WalletMetadata {

    private String encryptionAlgo;
    private String encryptionType;
    private String name;

}
