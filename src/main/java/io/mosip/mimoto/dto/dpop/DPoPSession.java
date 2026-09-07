package io.mosip.mimoto.dto.dpop;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * Server-side DPoP state that must survive the browser redirect.
 * Mirrors inji-vci-client {@code DPoPManager.Session}. PKCE lives in
 * {@code PkceSession}, stored under a separate HTTP session attribute.
 * Access token, credential {@code htu}, and {@code jkt} are not stored; they are
 * passed or computed at proof time. {@code issuerId} is stored so token and
 * credential requests stay bound to the issuer that created the session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DPoPSession implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String state;
    private String issuerId;
    private String alg;
    private String jwkJson;
    private String tokenHtu;
    private String issuerDPoPNonce;
}
