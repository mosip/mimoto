package io.mosip.residentapp.dto.mosip;

import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class CredentialShareResponse extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    private List<ErrorDTO> errors;

    private ResponseDTO response;
}
