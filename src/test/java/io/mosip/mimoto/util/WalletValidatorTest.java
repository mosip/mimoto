package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.exception.InvalidRequestException;
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

    @Test
    void testValidateWalletRequest_validData() {
        walletValidator.validateWalletRequest("user1", "wallet1", "123456");
    }

    @Test
    void testValidatePin_invalidPin() {

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            walletValidator.validateWalletRequest("user1", "My Wallet", "12");
        });

        assertEquals("invalid_request --> PIN must be numeric with 4 or 6 digits", exception.getMessage());
    }

    @Test
    void testValidateWalletName_invalidName() {

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            walletValidator.validateWalletRequest("user1", "My Wallet!@", "123456");
        });

        assertEquals("invalid_request --> Wallet name must be alphanumeric with allowed special characters", exception.getMessage());
    }

    @Test
    void testValidateWalletName_validName() {

        walletValidator.validateWalletRequest("user1", "wallet1", "123456");
    }
}
