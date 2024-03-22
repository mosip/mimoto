package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import java.util.List;

@Data
public class CredentialDisplayResponseDto {
    private List<CredentialIssuerDisplayResponse> display;
}
