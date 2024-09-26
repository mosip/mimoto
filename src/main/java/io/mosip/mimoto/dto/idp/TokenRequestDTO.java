package io.mosip.mimoto.dto.idp;

import lombok.Data;

@Data
public class TokenRequestDTO {
    private String grant_type;
    private String code;
    private String client_id;
    private String client_secret;
    private String redirect_uri;
    private String client_assertion_type;
    private String client_assertion;
}
