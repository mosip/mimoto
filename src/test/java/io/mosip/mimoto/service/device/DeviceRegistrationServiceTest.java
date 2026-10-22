package io.mosip.mimoto.service.device;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DevicePlatform;
import io.mosip.mimoto.model.DeviceRegistration;
import io.mosip.mimoto.model.DeviceRegistrationStatus;
import io.mosip.mimoto.repository.DeviceRegistrationRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class DeviceRegistrationServiceTest {

    private DeviceNonceService nonceService;
    private DeviceRegistrationRepository repository;
    private DeviceAttestationVerifier verifier;
    private DeviceRegistrationService service;
    private ECKey deviceKey;

    @Before
    public void setUp() throws Exception {
        nonceService = new DeviceNonceService(new InMemoryDeviceNonceStore(), new DeviceAttestationProperties());
        repository = mock(DeviceRegistrationRepository.class);
        when(repository.findById(anyString())).thenReturn(Optional.empty());
        verifier = mock(DeviceAttestationVerifier.class);
        when(verifier.platform()).thenReturn(DevicePlatform.ANDROID);
        when(verifier.verify(anyString(), anyString())).thenReturn(Map.of("appRecognitionVerdict", "PLAY_RECOGNIZED"));
        service = new DeviceRegistrationService(nonceService, repository, List.of(verifier));
        deviceKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    private String publicJwk() {
        return deviceKey.toPublicJWK().toJSONString();
    }

    @Test
    public void should_bindAttestationToNonceAndKeyThumbprint_when_registering() throws Exception {
        String nonce = nonceService.issue();

        service.register(DevicePlatform.ANDROID, nonce, publicJwk(), "integrity-token");

        String thumbprint = deviceKey.computeThumbprint().toString();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest((nonce + thumbprint).getBytes(StandardCharsets.UTF_8));
        verify(verifier).verify("integrity-token", Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    }

    @Test
    public void should_storeActivePublicKeyByThumbprint_when_newDevice() throws Exception {
        service.register(DevicePlatform.ANDROID, nonceService.issue(), publicJwk(), "integrity-token");

        ArgumentCaptor<DeviceRegistration> saved = ArgumentCaptor.forClass(DeviceRegistration.class);
        verify(repository).save(saved.capture());
        DeviceRegistration registration = saved.getValue();
        assertEquals(deviceKey.computeThumbprint().toString(), registration.getJwkThumbprint());
        assertEquals(DevicePlatform.ANDROID, registration.getPlatform());
        assertEquals(DeviceRegistrationStatus.ACTIVE, registration.getStatus());
        assertFalse(ECKey.parse(registration.getPublicKeyJwk()).isPrivate());
        assertEquals("PLAY_RECOGNIZED", registration.getAttestationVerdict().get("appRecognitionVerdict"));
    }

    @Test
    public void should_refreshVerdict_when_activeDeviceRegistersAgain() throws Exception {
        DeviceRegistration existing = new DeviceRegistration();
        existing.setJwkThumbprint(deviceKey.computeThumbprint().toString());
        existing.setStatus(DeviceRegistrationStatus.ACTIVE);
        when(repository.findById(existing.getJwkThumbprint())).thenReturn(Optional.of(existing));

        service.register(DevicePlatform.ANDROID, nonceService.issue(), publicJwk(), "integrity-token");

        verify(repository).save(existing);
        assertEquals("PLAY_RECOGNIZED", existing.getAttestationVerdict().get("appRecognitionVerdict"));
    }

    @Test
    public void should_rejectAndNotReactivate_when_deviceRevoked() throws Exception {
        DeviceRegistration revoked = new DeviceRegistration();
        revoked.setJwkThumbprint(deviceKey.computeThumbprint().toString());
        revoked.setStatus(DeviceRegistrationStatus.REVOKED);
        when(repository.findById(revoked.getJwkThumbprint())).thenReturn(Optional.of(revoked));

        DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                () -> service.register(DevicePlatform.ANDROID, nonceService.issue(), publicJwk(), "integrity-token"));

        assertEquals("device_revoked", e.getErrorCode());
        assertEquals(DeviceRegistrationStatus.REVOKED, revoked.getStatus());
        verify(repository, never()).save(any());
    }

    @Test
    public void should_rejectWithoutCallingVerifier_when_nonceReplayed() {
        String nonce = nonceService.issue();
        service.register(DevicePlatform.ANDROID, nonce, publicJwk(), "integrity-token");

        DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                () -> service.register(DevicePlatform.ANDROID, nonce, publicJwk(), "integrity-token"));

        assertEquals("invalid_nonce", e.getErrorCode());
        verify(verifier, times(1)).verify(anyString(), anyString());
    }

    @Test
    public void should_rejectWithoutConsumingNonce_when_keyInvalid() throws Exception {
        String nonce = nonceService.issue();
        RSAKey rsa = new RSAKeyGenerator(2048).generate();
        ECKey otherCurve = new ECKeyGenerator(Curve.P_384).generate();

        for (String bad : List.of("not-json", rsa.toPublicJWK().toJSONString(), otherCurve.toPublicJWK().toJSONString(), deviceKey.toJSONString())) {
            DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                    () -> service.register(DevicePlatform.ANDROID, nonce, bad, "integrity-token"));
            assertEquals("invalid_request", e.getErrorCode());
        }
        assertTrue(nonceService.consume(nonce));
        verifyNoInteractions(repository);
    }

    @Test
    public void should_reject_when_platformHasNoVerifier() {
        DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                () -> service.register(DevicePlatform.IOS, nonceService.issue(), publicJwk(), "attestation"));

        assertEquals("invalid_request", e.getErrorCode());
    }

    @Test
    public void should_notStore_when_attestationFails() {
        when(verifier.verify(anyString(), anyString()))
                .thenThrow(new DeviceAttestationException(io.mosip.mimoto.exception.ErrorConstants.ATTESTATION_FAILED, "nonce mismatch"));

        assertThrows(DeviceAttestationException.class,
                () -> service.register(DevicePlatform.ANDROID, nonceService.issue(), publicJwk(), "integrity-token"));
        verify(repository, never()).save(any());
    }
}
