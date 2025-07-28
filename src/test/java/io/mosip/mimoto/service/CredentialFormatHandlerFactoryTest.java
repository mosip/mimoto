package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.CredentialFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialFormatHandlerFactoryTest {

    private CredentialFormatHandler mockDcSdJwtHandler;
    private CredentialFormatHandler mockVcSdJwtHandler;
    private CredentialFormatHandler mockLdpVcHandler;

    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @BeforeEach
    void setUp() {
        mockDcSdJwtHandler = mock(CredentialFormatHandler.class);
        mockLdpVcHandler = mock(CredentialFormatHandler.class);
        mockVcSdJwtHandler = mock(CredentialFormatHandler.class);
    }

    @Test
    void constructorWithValidHandlersShouldInitializeHandlersMap() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        when(mockVcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.VC_SD_JWT.getFormat());

        List<CredentialFormatHandler> handlers = Arrays.asList(
                mockDcSdJwtHandler, mockLdpVcHandler, mockVcSdJwtHandler
        );

        // When
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // Then
        assertNotNull(credentialFormatHandlerFactory);
        verify(mockDcSdJwtHandler, times(1)).getSupportedFormat();
        verify(mockLdpVcHandler, times(1)).getSupportedFormat();
        verify(mockVcSdJwtHandler, times(1)).getSupportedFormat();
    }

    @Test
    void constructorWithEmptyHandlersListShouldInitializeEmptyMap() {
        // Given
        List<CredentialFormatHandler> handlers = Collections.emptyList();

        // When
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // Then
        assertNotNull(credentialFormatHandlerFactory);
    }

    @Test
    void getHandlerWithValidDcSdJwtFormatShouldReturnCorrectHandler() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockDcSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When
        CredentialFormatHandler result = credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat());

        // Then
        assertNotNull(result);
        assertEquals(mockDcSdJwtHandler, result);
    }

    @Test
    void getHandlerWithValidLdpVcFormatShouldReturnCorrectHandler() {
        // Given
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockLdpVcHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When
        CredentialFormatHandler result = credentialFormatHandlerFactory.getHandler(CredentialFormat.LDP_VC.getFormat());

        // Then
        assertNotNull(result);
        assertEquals(mockLdpVcHandler, result);
    }

    @Test
    void getHandlerWithUnsupportedFormatShouldThrowIllegalArgumentException() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockDcSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        String unsupportedFormat = "unsupported_format";

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> credentialFormatHandlerFactory.getHandler(unsupportedFormat)
        );

        assertEquals("Unsupported credential format: " + unsupportedFormat, exception.getMessage());
    }

    @Test
    void getHandlerWithNullFormatShouldThrowIllegalArgumentException() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockDcSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> credentialFormatHandlerFactory.getHandler(null)
        );

        assertEquals("Unsupported credential format: null", exception.getMessage());
    }

    @Test
    void getHandlerWithEmptyFormatShouldThrowIllegalArgumentException() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockDcSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        String emptyFormat = "";

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> credentialFormatHandlerFactory.getHandler(emptyFormat)
        );

        assertEquals("Unsupported credential format: ", exception.getMessage());
    }

    @Test
    void getHandlerWithMultipleHandlersShouldReturnCorrectHandlerForEachFormat() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());

        List<CredentialFormatHandler> handlers = Arrays.asList(
                mockDcSdJwtHandler, mockLdpVcHandler
        );
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When & Then
        CredentialFormatHandler sdJwtResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat());
        CredentialFormatHandler ldpVcResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.LDP_VC.getFormat());

        assertEquals(mockDcSdJwtHandler, sdJwtResult);
        assertEquals(mockLdpVcHandler, ldpVcResult);
    }

    @Test
    void getHandlerWithVcSdJwtFormatButNoDcSdJwtHandlerShouldThrowException() {
        // Given - Only LDP VC handler available, no DC_SD_JWT handler
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockLdpVcHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat())
        );

        assertEquals("Unsupported credential format: " + CredentialFormat.VC_SD_JWT.getFormat(),
                exception.getMessage());
    }

    @Test
    void constructorWithNullHandlerInListShouldHandleGracefully() {
        // Given
        when(mockDcSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockDcSdJwtHandler, null);

        // When & Then - Should handle null handler gracefully (might throw NPE during construction)
        assertThrows(NullPointerException.class, () -> new CredentialFormatHandlerFactory(handlers));
    }
}
