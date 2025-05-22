package io.mosip.mimoto.util;

import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WalletValidator.class)
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletValidatorTest {

    @Autowired
    private WalletValidator walletValidator;

    @Test
    void testValidateWalletRequest_validData() {
        walletValidator.validateUserId("user1");
        walletValidator.validateWalletName("wallet1");
        walletValidator.validateWalletPin("123456");
    }

    @Test
    void testValidatePin_invalidPin() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            walletValidator.validateUserId("user1");
            walletValidator.validateWalletName("My Wallet");
            walletValidator.validateWalletPin("12");
        });

        assertEquals("invalid_request --> PIN must be numeric with 4 or 6 digits", exception.getMessage());
    }

    @Test
    void testValidateWalletName_invalidName() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            walletValidator.validateUserId("user1");
            walletValidator.validateWalletName("My Wallet!@");
            walletValidator.validateWalletPin("123456");
        });

        assertEquals("invalid_request --> Wallet name must be alphanumeric with allowed special characters", exception.getMessage());
    }

    @Test
    void testValidateWalletName_validName() {
        walletValidator.validateUserId("user1");
        walletValidator.validateWalletName("wallet1");
        walletValidator.validateWalletPin("123456");
    }
}
