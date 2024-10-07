/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package io.mosip.mimoto.util;

import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.mimoto.AttestationStatement;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

/**
 * Verify the device attestation statement offline.
 */
@Slf4j
@Component
public class AttestationOfflineVerify {

    private final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();

    public AttestationStatement parseAndVerify(String signedAttestationStatment) throws Exception {
        // Parse JSON Web Signature format.
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AttestationStatement.class).parse(signedAttestationStatment);
        } catch (IOException | IllegalArgumentException e) {
            throw new Exception(signedAttestationStatment + " is not valid JWS format.");
        }

        // Verify the signature of the JWS and retrieve the signature certificate.
        X509Certificate cert;
        try {
            cert = jws.verifySignature();
            if (cert == null) {
                throw new Exception("Signature verification failed.");
            }
        } catch (GeneralSecurityException e) {
            throw new Exception("Error during cryptographic verification of the JWS signature.");
        }

        // Verify the hostname of the certificate.
        if (!verifyHostname("attest.android.com", cert)) {
            throw new Exception("Certificate isn't issued for the hostname attest.android.com.");
        }

        log.info("Sucessfully verified the signature of the attestation statement using offline method.");

        // Extract and use the payload data.
        AttestationStatement stmt = (AttestationStatement) jws.getPayload();
        return stmt;
    }

    /**
     * Verifies that the certificate matches the specified hostname.
     * Uses the {@link DefaultHostnameVerifier} from the Apache HttpClient library
     * to confirm that the hostname matches the certificate.
     *
     * @param hostname
     * @param leafCert
     * @return
     */
    private boolean verifyHostname(String hostname, X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            HOSTNAME_VERIFIER.verify(hostname, leafCert);
            return true;
        } catch (SSLException e) {
            log.error("Error when verifying hostname", e);
        }

        return false;
    }
}
