package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.WalletRequestDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WalletValidator.class)
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletValidatorTest {

    @Autowired
    private WalletValidator walletValidator;

    @Mock
    private WalletRequestDto walletRequestDto;

    @BeforeEach
    void setUp() {
        when(walletRequestDto.getPin()).thenReturn("1234");
        when(walletRequestDto.getName()).thenReturn("My Wallet");
    }

    @Test
    void testValidateWalletRequest_validData() {
        walletValidator.validateWalletRequest(walletRequestDto);
    }

    @Test
    void testValidatePin_invalidPin() {
        when(walletRequestDto.getPin()).thenReturn("12");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            walletValidator.validateWalletRequest(walletRequestDto);
        });

        assertEquals("Pin should be numeric with 4 or 6 digits.", exception.getMessage());
    }

    @Test
    void testValidateWalletName_invalidName() {
        // Ensure valid pin for wallet name test
        when(walletRequestDto.getPin()).thenReturn("1234");
        when(walletRequestDto.getName()).thenReturn("My Wallet!@");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            walletValidator.validateWalletRequest(walletRequestDto);
        });

        assertEquals("Wallet name should be alphanumeric with spaces and a few allowed special characters.", exception.getMessage());
    }

    @Test
    void testValidateWalletName_validName() {
        // Ensure valid pin for wallet name test
        when(walletRequestDto.getPin()).thenReturn("123456");
        when(walletRequestDto.getName()).thenReturn("Valid Wallet 123");

        walletValidator.validateWalletRequest(walletRequestDto);
    }
}
