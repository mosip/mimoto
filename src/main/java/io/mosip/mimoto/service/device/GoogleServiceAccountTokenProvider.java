package io.mosip.mimoto.service.device;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Obtains OAuth access tokens for a Google service account using the JWT bearer grant
 * (Google "OAuth 2.0 for Server to Server Applications", HTTP/REST variant), without the Google client library.
 * Tokens are cached until shortly before they expire.
 */
@Slf4j
@Component
public class GoogleServiceAccountTokenProvider {

    static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    static final String JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final long ASSERTION_LIFETIME_SECONDS = 3600;
    private static final long REFRESH_MARGIN_SECONDS = 60;

    private final RestTemplate restTemplate;
    private final DeviceAttestationProperties properties;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    private ServiceAccount serviceAccount;
    private String cachedToken;
    private Instant cachedTokenExpiry = Instant.EPOCH;

    @Autowired
    public GoogleServiceAccountTokenProvider(@Qualifier("playIntegrityRestTemplate") RestTemplate restTemplate,
                                             DeviceAttestationProperties properties,
                                             ObjectMapper objectMapper) {
        this(restTemplate, properties, objectMapper, Clock.systemUTC());
    }

    GoogleServiceAccountTokenProvider(RestTemplate restTemplate, DeviceAttestationProperties properties,
                                      ObjectMapper objectMapper, Clock clock) {
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public synchronized String getAccessToken(String scope) {
        Instant now = clock.instant();
        if (cachedToken != null && now.isBefore(cachedTokenExpiry.minusSeconds(REFRESH_MARGIN_SECONDS))) {
            return cachedToken;
        }
        ServiceAccount account = serviceAccount();
        String assertion = signAssertion(account, scope, now);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", JWT_BEARER_GRANT);
        form.add("assertion", assertion);

        TokenResponse response = restTemplate.postForObject(TOKEN_ENDPOINT, new HttpEntity<>(form, headers), TokenResponse.class);
        if (response == null || StringUtils.isBlank(response.accessToken())) {
            throw new IllegalStateException("Google token endpoint returned no access token");
        }
        cachedToken = response.accessToken();
        cachedTokenExpiry = now.plusSeconds(response.expiresIn() > 0 ? response.expiresIn() : ASSERTION_LIFETIME_SECONDS);
        return cachedToken;
    }

    private String signAssertion(ServiceAccount account, String scope, Instant now) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(account.clientEmail())
                    .claim("scope", scope)
                    .audience(TOKEN_ENDPOINT)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ASSERTION_LIFETIME_SECONDS)))
                    .build();
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT);
            if (StringUtils.isNotBlank(account.privateKeyId())) {
                header.keyID(account.privateKeyId());
            }
            SignedJWT jwt = new SignedJWT(header.build(), claims);
            jwt.sign(new RSASSASigner(account.privateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to sign the service account assertion", e);
        }
    }

    private ServiceAccount serviceAccount() {
        if (serviceAccount == null) {
            serviceAccount = loadServiceAccount(properties.getGoogle().getServiceAccountKeyPath());
        }
        return serviceAccount;
    }

    private ServiceAccount loadServiceAccount(String keyPath) {
        if (StringUtils.isBlank(keyPath)) {
            throw new IllegalStateException("wallet.device-attestation.google.service-account-key-path is not set");
        }
        try {
            KeyFile keyFile = objectMapper.readValue(Files.readString(Path.of(keyPath)), KeyFile.class);
            if (StringUtils.isAnyBlank(keyFile.clientEmail(), keyFile.privateKey())) {
                throw new IllegalStateException("Service account key file is missing client_email or private_key");
            }
            return new ServiceAccount(keyFile.clientEmail(), keyFile.privateKeyId(), parsePkcs8RsaKey(keyFile.privateKey()));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load the service account key file", e);
        }
    }

    static PrivateKey parsePkcs8RsaKey(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private record ServiceAccount(String clientEmail, String privateKeyId, PrivateKey privateKey) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record KeyFile(@JsonProperty("client_email") String clientEmail,
                   @JsonProperty("private_key_id") String privateKeyId,
                   @JsonProperty("private_key") String privateKey) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record TokenResponse(@JsonProperty("access_token") String accessToken,
                         @JsonProperty("expires_in") long expiresIn,
                         @JsonProperty("token_type") String tokenType) {
    }
}
