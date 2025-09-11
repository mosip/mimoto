package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

@Slf4j
public class WalletPresentationUtil {

    private WalletPresentationUtil() {
        throw new UnsupportedOperationException("WalletPresentationUtil class should not be instantiated");
    }
    public static Verifier mapToVerifier(VerifierDTO verifierDTO) {
        Map<String, ?> clientMetadataMap = verifierDTO.getClientMetadata();

        if (clientMetadataMap == null) {
            log.info("clientMetadata is null for verifierDTO: " + verifierDTO.getClientId());
            return new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), null);
        }

        Jwks jwks = extractJwks(clientMetadataMap);

        ClientMetadata clientMetadata = new ClientMetadata(
                getStringOrNull(clientMetadataMap, "client_name"),
                getStringOrNull(clientMetadataMap, "logo_uri"),
                (Map<String, Map<String, List<String>>>) clientMetadataMap.get("vp_formats"),
                getStringOrNull(clientMetadataMap, "authorization_encrypted_response_alg"),
                getStringOrNull(clientMetadataMap, "authorization_encrypted_response_enc"),
                jwks
        );

        return new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), clientMetadata);
    }

    private static Jwks extractJwks(Map<String, ?> clientMetadataMap) {
        Object jwksObj = clientMetadataMap.get("jwks");
        if (jwksObj == null) return null;

        if (!(jwksObj instanceof Map)) {
            throw new IllegalArgumentException("'jwks' must be a Map<String, Object>");
        }

        Map<String, Object> jwksMap = (Map<String, Object>) jwksObj;
        Object keysObj = jwksMap.get("keys");
        if (keysObj == null) return null;

        if (!(keysObj instanceof List)) {
            throw new IllegalArgumentException("'keys' must be a List<Map<String, String>>");
        }

        List<Map<String, String>> keys = (List<Map<String, String>>) keysObj;

        return new Jwks(keys.stream().map(WalletPresentationUtil::mapToJwk).toList());
    }

    private static Jwk mapToJwk(Map<String, String> jwk) {
        return new Jwk(
                jwk.get("kty"),
                jwk.get("use"),
                jwk.get("crv"),
                jwk.get("x"),
                jwk.get("alg"),
                jwk.get("kid"),
                jwk.get("y")
        );
    }

    private static String getStringOrNull(Map<String, ?> map, String key) {
        Object value = map.get(key);
        return (value instanceof String stringValue) ? stringValue : null;
    }
}

