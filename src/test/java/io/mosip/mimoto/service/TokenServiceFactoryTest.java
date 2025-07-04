package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class TokenServiceFactoryTest {

    @InjectMocks
    private TokenServiceFactory tokenServiceFactory;

    @Mock
    private TokenService googleTokenService;

    @Before
    public void setUp() {
        Map<String, TokenService> tokenServices = new HashMap<>();
        tokenServices.put("google", googleTokenService);
        tokenServiceFactory = new TokenServiceFactory(tokenServices);
    }

    @Test
    public void testGetTokenService_ValidProvider_ReturnsService() throws OAuth2AuthenticationException {
        // Act
        TokenService result = tokenServiceFactory.getTokenService("google");

        // Assert
        assertNotNull(result);
        assertEquals(googleTokenService, result);
    }

    @Test
    public void testGetTokenService_CaseInsensitiveProvider_ReturnsService() throws OAuth2AuthenticationException {
        // Act
        TokenService result = tokenServiceFactory.getTokenService("GOOGLE");

        // Assert
        assertNotNull(result);
        assertEquals(googleTokenService, result);
    }

    @Test
    public void testGetTokenService_UnsupportedProvider_ThrowsException() {
        // Arrange
        String invalidProvider = "facebook";

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> tokenServiceFactory.getTokenService(invalidProvider));

        assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertEquals("invalid_request --> Unsupported provider: " + invalidProvider, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
    }

}
