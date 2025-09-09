package io.mosip.mimoto.service;

import io.mosip.mimoto.service.impl.OpenID4VPFactory;
import io.mosip.openID4VP.OpenID4VP;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(MockitoJUnitRunner.class)
@Slf4j
public class OpenID4VPFactoryTest {

    @Test
    public void testCreate_returnsValidOpenID4VP() {
        OpenID4VPFactory factory = new OpenID4VPFactory();

        OpenID4VP openID4VP = factory.create("presentation-123");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }
}
