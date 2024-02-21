package io.mosip.mimoto.dto.v2;

import lombok.Data;

import java.util.List;

@Data
public class CredentialDisplayResponseDto {
    private List<CredentialIssuerDisplayResponse> display;
}
