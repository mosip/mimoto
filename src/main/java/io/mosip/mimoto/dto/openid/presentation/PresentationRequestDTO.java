package io.mosip.mimoto.dto.openid.presentation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PresentationRequestDTO {

    String response_type;
    String resource;
    String presentation_definition;
    String client_id;
    String redirect_uri;

}
