package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
//TODO: remove this unused DTO
public class CachedUserMetadataDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    @Schema(description = "Display name of the user provided by the Identity Provider")
    private String displayName;

    @Schema(description = "Profile picture of the user provided by the Identity Provider")
    private String profilePictureUrl;

    @Schema(description = "Email of the user provided by the Identity Provider")
    private String email;

    @Schema(description = "Wallet id of the user in use")
    private String walletId;
}