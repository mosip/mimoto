package io.mosip.mimoto.util;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
@Slf4j
class WalletUtilTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @InjectMocks
    private WalletUtil walletUtil;

    private String pin;
    private String name;
    private String userId;
    private SecretKey encryptionKey;
    private String encryptedPrivateKey;
    private String encryptedWalletKey;
    private String decryptedWalletKey;
    private String encryptionAlgorithm;
    private String encryptionType;

    @BeforeEach
    void setUp() throws Exception {
        pin = "1234";
        name = "default";
        userId = UUID.randomUUID().toString();
        encryptionKey = KeyGenerationUtil.generateEncryptionKey("AES", 256);
        encryptedPrivateKey = "encryptedPrivateKey";
        encryptedWalletKey = "encryptedWalletKey";
        decryptedWalletKey = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
        encryptionAlgorithm = "AES";
        encryptionType = "encryptWithPin";
    }

    @Test
    void shouldDecryptWalletKeySuccessfully() throws DecryptionException {
        when(encryptionDecryptionUtil.decryptWithPin(encryptedWalletKey, pin)).thenReturn(decryptedWalletKey);

        String decrypted = walletUtil.decryptWalletKey(encryptedWalletKey, pin);

        assertEquals(decryptedWalletKey, decrypted);
    }

    @Test
    void shouldCreateNewWalletSuccessfully() throws Exception {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.saveWallet(userId, name, pin, encryptionKey, encryptionAlgorithm, encryptionType);

        assertNotNull(walletId);
    }

    @Test
    void shouldCreateEd25519WalletSuccessfully() throws Exception {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.createWallet(userId, name, pin);

        assertNotNull(walletId);
    }

    @Test
    void shouldVerifyWalletObjectOnCreateNewWallet() throws Exception {
        when(encryptionDecryptionUtil.encryptKeyWithPin(any(SecretKey.class), any(String.class))).thenReturn(encryptedWalletKey);
        when(encryptionDecryptionUtil.encryptWithAES(any(SecretKey.class), any(byte[].class))).thenReturn(encryptedPrivateKey);

        String walletId = walletUtil.saveWallet(userId, name, pin, encryptionKey, encryptionAlgorithm, encryptionType);

        ArgumentCaptor<Wallet> walletCaptor = ArgumentCaptor.forClass(Wallet.class);
        verify(walletRepository).save(walletCaptor.capture());

        Wallet savedWallet = walletCaptor.getValue();

        assertEquals(walletId, savedWallet.getId());
        assertEquals(userId, savedWallet.getUserId());
        assertEquals(name, savedWallet.getWalletMetadata().getName());
        assertEquals(encryptedWalletKey, savedWallet.getWalletKey());
        assertEquals(encryptionAlgorithm, savedWallet.getWalletMetadata().getEncryptionAlgo());
        assertEquals(encryptionType, savedWallet.getWalletMetadata().getEncryptionType());
        assertNotNull(savedWallet.getProofSigningKeys());
        assertEquals(4, savedWallet.getProofSigningKeys().size());
    }

    // Tests for validateUserId
    @Test
    void testValidUserId() {
        assertDoesNotThrow(() -> WalletUtil.validateUserId("validUserId"));
    }

    @Test
    void testNullUserId() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> WalletUtil.validateUserId(null));

        assertEquals("invalid_request", ex.getErrorCode());
        assertEquals("invalid_request --> User ID not found in session", ex.getMessage());
    }
}