package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.KeyMetadata;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.repository.WalletRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WalletUtilTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private CryptomanagerService cryptomanagerService;

    @InjectMocks
    private WalletUtil walletUtil;

    private String pin;
    private String userId;
    private KeyPair keyPair;
    private SecretKey encryptionKey;
    private String encryptedPrivateKey;
    private String encryptedWalletKey;
    private String decryptedWalletKey;
    private String publicKeyBase64;
    private String encryptionAlgorithm;
    private String encryptionType;
    private CryptoWithPinResponseDto cryptoResponseDto;

    @BeforeEach
    void setUp() throws Exception {
        pin = "1234";
        userId = UUID.randomUUID().toString();
        keyPair = EncryptionDecryptionUtil.generateKeyPair("Ed25519");
        encryptionKey = EncryptionDecryptionUtil.generateEncryptionKey("AES", 256);
        encryptedPrivateKey = EncryptionDecryptionUtil.encryptPrivateKeyWithAES(encryptionKey, keyPair.getPrivate());
        encryptedWalletKey = "encryptedWalletKey";
        decryptedWalletKey = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
        publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        encryptionAlgorithm = "AES";
        encryptionType = "encryptWithPin";
        cryptoResponseDto = new CryptoWithPinResponseDto();
    }

    @Test
    void decryptWalletKey_shouldDecryptSuccessfully() {
        cryptoResponseDto.setData(decryptedWalletKey);
        when(cryptomanagerService.decryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);

        String decrypted = walletUtil.decryptWalletKey(encryptedWalletKey, pin);

        assertEquals(decryptedWalletKey, decrypted);
    }

    @Test
    void createNewWallet_shouldCreateWalletSuccessfully() throws Exception {
        cryptoResponseDto.setData(encryptedWalletKey);
        when(cryptomanagerService.encryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);
        String walletId = walletUtil.createNewWallet(userId, pin, keyPair, encryptionKey, encryptionAlgorithm, encryptionType);

        assertNotNull(walletId);
    }

    @Test
    void createEd25519AlgoWallet_shouldCreateEd25519WalletSuccessfully() throws Exception {
        cryptoResponseDto.setData(encryptedWalletKey);
        when(cryptomanagerService.encryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);
        String walletId = walletUtil.createEd25519AlgoWallet(userId, pin);

        assertNotNull(walletId);
    }


    @Test
    void createNewWallet_verifyWalletObject() throws Exception {
        cryptoResponseDto.setData(encryptedWalletKey);
        when(cryptomanagerService.encryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);
        String walletId = walletUtil.createNewWallet(userId, pin, keyPair, encryptionKey, encryptionAlgorithm, encryptionType);

        ArgumentCaptor<Wallet> walletCaptor = ArgumentCaptor.forClass(Wallet.class);
        verify(walletRepository).save(walletCaptor.capture());

        Wallet savedWallet = walletCaptor.getValue();

        assertEquals(walletId, savedWallet.getId());
        assertEquals(userId, savedWallet.getUserId());
        assertEquals(keyPair.getPublic().getAlgorithm(), savedWallet.getKeyMetadata().getAlgorithmName());
        assertEquals(publicKeyBase64, savedWallet.getPublicKey());
        assertEquals(encryptedPrivateKey, savedWallet.getSecretKey());
        assertEquals(encryptedWalletKey, savedWallet.getWalletKey());
        assertEquals(encryptionAlgorithm, savedWallet.getWalletMetadata().getEncryptionAlgo());
        assertEquals(encryptionType, savedWallet.getWalletMetadata().getEncryptionType());
    }
}