package io.mosip.mimoto.service.device;

import io.mosip.mimoto.model.DevicePlatform;

import java.util.Map;

/**
 * Verifies a platform attestation that is bound to an expected nonce.
 */
public interface DeviceAttestationVerifier {

    DevicePlatform platform();

    /**
     * @param attestation   the platform attestation sent by the wallet (e.g. a Play Integrity token)
     * @param expectedNonce the value the attestation must have been requested for
     * @return a verdict summary to keep for audit
     * @throws io.mosip.mimoto.exception.DeviceAttestationException when the attestation is not acceptable
     */
    Map<String, Object> verify(String attestation, String expectedNonce);
}
