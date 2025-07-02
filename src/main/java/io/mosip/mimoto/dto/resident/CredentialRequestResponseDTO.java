package io.mosip.mimoto.dto.resident;

import java.util.ArrayList;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.Data;

@Data
public class CredentialRequestResponseDTO {
    private String id;
    private String version;
    String str;
    private String responsetime;
    private Object metadata;
    @NotNull
    @Valid
    private CredentialRequestResponseInnerResponseDTO response;

    private List<ErrorDTO> errors = new ArrayList<>();
}
