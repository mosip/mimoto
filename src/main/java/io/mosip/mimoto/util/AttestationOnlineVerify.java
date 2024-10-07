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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Base64;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.mimoto.AttestationStatement;
import io.mosip.mimoto.dto.mimoto.AttestationVerificationRequestDTO;
import io.mosip.mimoto.dto.mimoto.AttestationVerificationResponseDTO;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Verify the device attestation statement online.
 * You must add your API key for the Android Device Verification API here
 * ({@link #API_KEY}),
 * otherwise all requests will fail.
 */
@Component
@Slf4j
public class AttestationOnlineVerify {

    private final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    private final JsonFactory JSON_FACTORY = new JacksonFactory();

    // Please use the Google Developers Console
    // (https://console.developers.google.com/)
    // to create a project, enable the Android Device Verification API, generate an
    // API key
    // and add it here.
    @Value("${safetynet.api.url}")
    private String URL;

    private AttestationVerificationResponseDTO onlineVerify(AttestationVerificationRequestDTO request)
            throws Exception {
        // Prepare a request to the Device Verification API and set a parser for JSON
        // data.
        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
            @Override
            public void initialize(HttpRequest request) {
                request.setParser(new JsonObjectParser(JSON_FACTORY));
            }
        });
        GenericUrl url = new GenericUrl(URL);
        HttpRequest httpRequest;
        try {
            // Post the request with the verification statement to the API.
            httpRequest = requestFactory.buildPostRequest(url, new JsonHttpContent(JSON_FACTORY,
                    request));
            // Parse the returned data as a verification response.
            return httpRequest.execute().parseAs(AttestationVerificationResponseDTO.class);
        } catch (IOException e) {
            throw new Exception("Network error while connecting to the Google Service " + URL + ".\n"
                    + "Ensure that you added your API key and enabled the Android device verification API.");
        }
    }

    /**
     * Extracts the data part from a JWS signature.
     * @throws Exception
     */
    private byte[] extractJwsData(String jws) throws Exception {
        // The format of a JWS is:
        // <Base64url encoded header>.<Base64url encoded JSON data>.<Base64url encoded
        // signature>
        // Split the JWS into the 3 parts and return the JSON data part.
        String[] parts = jws.split("[.]");
        if (parts.length != 3) {
            throw new Exception("Illegal JWS signature format. The JWS consists of " + parts.length + " parts instead of 3.");
        }
        return Base64.decodeBase64(parts[1]);
    }

    public AttestationStatement parseAndVerify(String signedAttestationStatment) throws Exception {
        // Send the signed attestation statement to the API for verification.
        AttestationVerificationRequestDTO request = new AttestationVerificationRequestDTO(signedAttestationStatment);
        AttestationVerificationResponseDTO response = onlineVerify(request);
        if (response == null) {
            return null;
        }

        if (response.error != null) {
            throw new Exception("The API encountered an error processing this request: " + response.error);
        }

        if (!response.isValidSignature) {
            throw new Exception("The cryptographic signature of the attestation statement couldn't be " + "verified.");
        }

        log.info("Sucessfully verified the signature of the attestation statement using online method.");

        // The signature is valid, extract the data JSON from the JWS signature.
        byte[] data = extractJwsData(signedAttestationStatment);

        // Parse and use the data JSON.
        try {
            return JSON_FACTORY.fromInputStream(new ByteArrayInputStream(data),
                    AttestationStatement.class);
        } catch (IOException e) {
            throw new Exception("Failed to parse the data portion of the JWS as valid " +"JSON.");
        }
    }
}
