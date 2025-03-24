package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserMetadataDTO {
    @JsonProperty("display_name")
    @Schema(description = "Display name of the user provided by the Identity Provider")
    private String displayName;

    @JsonProperty("profile_picture_url")
    @Schema(description = "Profile picture of the user provided by the Identity Provider")
    private String profilePictureUrl;

    @JsonProperty("email")
    @Schema(description = "Email of the user provided by the Identity Provider")
    private String email;
}