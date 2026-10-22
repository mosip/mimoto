package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import org.junit.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class DeviceNonceServiceTest {

    private DeviceNonceService serviceWithTtl(long ttlSeconds) {
        DeviceAttestationProperties properties = new DeviceAttestationProperties();
        properties.setNonceTtlSeconds(ttlSeconds);
        return new DeviceNonceService(new InMemoryDeviceNonceStore(), properties);
    }

    @Test
    public void should_issueUnpadded256BitBase64UrlNonce_when_issued() {
        String nonce = serviceWithTtl(120).issue();

        assertTrue(nonce.matches("^[A-Za-z0-9_-]{43}$"), nonce);
    }

    @Test
    public void should_issueDistinctNonces_when_issuedRepeatedly() {
        DeviceNonceService service = serviceWithTtl(120);
        Set<String> nonces = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            nonces.add(service.issue());
        }
        assertEquals(1000, nonces.size());
    }

    @Test
    public void should_acceptNonceOnlyOnce_when_consumedTwice() {
        DeviceNonceService service = serviceWithTtl(120);
        String nonce = service.issue();

        assertTrue(service.consume(nonce));
        assertFalse(service.consume(nonce));
    }

    @Test
    public void should_rejectNonce_when_notIssuedByService() {
        DeviceNonceService service = serviceWithTtl(120);

        assertFalse(service.consume("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    public void should_rejectNonce_when_blankOrMalformed() {
        DeviceNonceService service = serviceWithTtl(120);

        assertFalse(service.consume(null));
        assertFalse(service.consume(""));
        assertFalse(service.consume("short"));
        assertFalse(service.consume("not base64url!not base64url!not base64url!"));
    }

    @Test
    public void should_rejectNonce_when_expired() throws InterruptedException {
        InMemoryDeviceNonceStore store = new InMemoryDeviceNonceStore();
        store.put("expiring", Duration.ofMillis(50));
        Thread.sleep(200);

        assertFalse(store.consume("expiring"));
    }

    @Test
    public void should_reportConfiguredTtl_when_asked() {
        assertEquals(120, serviceWithTtl(120).ttlSeconds());
    }
}
