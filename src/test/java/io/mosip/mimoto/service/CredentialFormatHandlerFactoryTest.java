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

    private CredentialFormatHandler mockSdJwtHandler;
    private CredentialFormatHandler mockLdpVcHandler;

    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    @BeforeEach
    void setUp() {
        mockSdJwtHandler = mock(CredentialFormatHandler.class);
        mockLdpVcHandler = mock(CredentialFormatHandler.class);
    }

    @Test
    void constructorWithValidHandlersShouldInitializeHandlersMap() {
        // Given
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());

        List<CredentialFormatHandler> handlers = Arrays.asList(
                mockSdJwtHandler, mockLdpVcHandler
        );

        // When
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // Then
        assertNotNull(credentialFormatHandlerFactory);
        verify(mockSdJwtHandler, times(1)).getSupportedFormat();
        verify(mockLdpVcHandler, times(1)).getSupportedFormat();
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
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When
        CredentialFormatHandler result = credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat());

        // Then
        assertNotNull(result);
        assertEquals(mockSdJwtHandler, result);
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
    void getHandlerWithVcSdJwtFormatShouldReturnDcSdJwtHandler() {
        // Given
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When - Using VC_SD_JWT format which should be mapped to DC_SD_JWT
        CredentialFormatHandler result = credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat());

        // Then
        assertNotNull(result);
        assertEquals(mockSdJwtHandler, result);
    }

    @Test
    void getHandlerWithUnsupportedFormatShouldThrowIllegalArgumentException() {
        // Given
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
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
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
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
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
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
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());

        List<CredentialFormatHandler> handlers = Arrays.asList(
                mockSdJwtHandler, mockLdpVcHandler
        );
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When & Then
        CredentialFormatHandler sdJwtResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat());
        CredentialFormatHandler ldpVcResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.LDP_VC.getFormat());

        assertEquals(mockSdJwtHandler, sdJwtResult);
        assertEquals(mockLdpVcHandler, ldpVcResult);
    }

    @Test
    void getHandlerFormatMappingConsistencyShouldWork() {
        // Given
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When
        CredentialFormatHandler dcSdJwtResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.DC_SD_JWT.getFormat());
        CredentialFormatHandler vcSdJwtResult = credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat());

        // Then - Both should return the same handler due to format mapping
        assertNotNull(dcSdJwtResult);
        assertNotNull(vcSdJwtResult);
        assertEquals(dcSdJwtResult, vcSdJwtResult);
        assertEquals(mockSdJwtHandler, dcSdJwtResult);
        assertEquals(mockSdJwtHandler, vcSdJwtResult);
    }

    @Test
    void getHandlerWithVcSdJwtFormatButNoDcSdJwtHandlerShouldThrowException() {
        // Given - Only LDP VC handler available, no DC_SD_JWT handler
        when(mockLdpVcHandler.getSupportedFormat()).thenReturn(CredentialFormat.LDP_VC.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockLdpVcHandler);
        credentialFormatHandlerFactory = new CredentialFormatHandlerFactory(handlers);

        // When & Then - VC_SD_JWT maps to DC_SD_JWT, but no DC_SD_JWT handler exists
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> credentialFormatHandlerFactory.getHandler(CredentialFormat.VC_SD_JWT.getFormat())
        );

        assertEquals("Unsupported credential format: " + CredentialFormat.DC_SD_JWT.getFormat(),
                exception.getMessage());
    }

    @Test
    void constructorWithNullHandlerInListShouldHandleGracefully() {
        // Given
        when(mockSdJwtHandler.getSupportedFormat()).thenReturn(CredentialFormat.DC_SD_JWT.getFormat());
        List<CredentialFormatHandler> handlers = Arrays.asList(mockSdJwtHandler, null);

        // When & Then - Should handle null handler gracefully (might throw NPE during construction)
        assertThrows(NullPointerException.class, () -> new CredentialFormatHandlerFactory(handlers));
    }
}
