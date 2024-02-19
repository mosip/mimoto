package io.mosip.mimoto.dto.v2;

import lombok.Data;

@Data
public class VCCredentialIssueBody {
    private VCCredentialProperties credential;
    private String credentialSchemaId;
    private String createdAt;
    private String createdBy;
    private String updatedAt;
    private String updatedBy;
}
