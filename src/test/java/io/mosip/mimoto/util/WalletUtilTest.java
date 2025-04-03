package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.repository.WalletRepository;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Slf4j
class WalletUtilTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private CryptomanagerService cryptomanagerService;

    @InjectMocks
    private WalletUtil walletUtil;

    private String pin;
    private String name;
    private String userId;
    private KeyPair keyPair;
    private SecretKey encryptionKey;
    private String encryptedWalletKey;
    private String decryptedWalletKey;
    private String publicKeyBase64;
    private String encryptionAlgorithm;
    private String encryptionType;
    private CryptoWithPinResponseDto cryptoResponseDto;

    @BeforeEach
    void setUp() throws Exception {
        pin = "1234";
        name = "default";
        userId = UUID.randomUUID().toString();
        keyPair = EncryptionDecryptionUtil.generateKeyPair("Ed25519");
        encryptionKey = EncryptionDecryptionUtil.generateEncryptionKey("AES", 256);
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
        String walletId = walletUtil.createNewWallet(userId, pin, name, keyPair, encryptionKey, encryptionAlgorithm, encryptionType);

        assertNotNull(walletId);
    }

    @Test
    void createEd25519AlgoWallet_shouldCreateEd25519WalletSuccessfully() throws Exception {
        cryptoResponseDto.setData(encryptedWalletKey);
        when(cryptomanagerService.encryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);
        String walletId = walletUtil.createEd25519AlgoWallet(userId, name, pin);

        assertNotNull(walletId);
    }


    @Test
    void createNewWallet_verifyWalletObject() throws Exception {
        cryptoResponseDto.setData(encryptedWalletKey);
        when(cryptomanagerService.encryptWithPin(any(CryptoWithPinRequestDto.class))).thenReturn(cryptoResponseDto);
        String walletId = walletUtil.createNewWallet(userId, pin, name, keyPair, encryptionKey, encryptionAlgorithm, encryptionType);

        ArgumentCaptor<Wallet> walletCaptor = ArgumentCaptor.forClass(Wallet.class);
        verify(walletRepository).save(walletCaptor.capture());

        Wallet savedWallet = walletCaptor.getValue();

        assertEquals(walletId, savedWallet.getId());
        assertEquals(userId, savedWallet.getUserId());
        assertEquals(keyPair.getPublic().getAlgorithm(), savedWallet.getProofSigningKeys().get(0).getKeyMetadata().getAlgorithmName());
        assertEquals(publicKeyBase64, savedWallet.getProofSigningKeys().get(0).getPublicKey());
        assertFalse(savedWallet.getProofSigningKeys().get(0).getSecretKey().isEmpty(), "Encrypted private key should not be empty");
        assertEquals(encryptedWalletKey, savedWallet.getWalletKey());
        assertEquals(encryptionAlgorithm, savedWallet.getWalletMetadata().getEncryptionAlgo());
        assertEquals(encryptionType, savedWallet.getWalletMetadata().getEncryptionType());
    }

    @Test
    void testIVChangesButCiphertextRemainsSameForSameEncryptionKeyAndSecretKey() throws Exception {
        String encryptedPrivateKey1 = EncryptionDecryptionUtil.encrypt(encryptionKey, keyPair.getPrivate().getEncoded());
        String encryptedPrivateKey2 = EncryptionDecryptionUtil.encrypt(encryptionKey, keyPair.getPrivate().getEncoded());

        byte[] encryptedBytes1 = Base64.getDecoder().decode(encryptedPrivateKey1);
        byte[] encryptedBytes2 = Base64.getDecoder().decode(encryptedPrivateKey2);

        byte[] iv1 = Arrays.copyOfRange(encryptedBytes1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(encryptedBytes2, 0, 12);

        byte[] decryptedPrivateKey1Bytes = EncryptionDecryptionUtil.decrypt(encryptionKey, encryptedPrivateKey1);
        byte[] decryptedPrivateKey2Bytes = EncryptionDecryptionUtil.decrypt(encryptionKey, encryptedPrivateKey2);
        PrivateKey decryptedPrivateKey1 = EncryptionDecryptionUtil.bytesToPrivateKey(decryptedPrivateKey1Bytes, "ed25519");
        PrivateKey decryptedPrivateKey2 = EncryptionDecryptionUtil.bytesToPrivateKey(decryptedPrivateKey2Bytes,"ed25519");

        assertFalse(Arrays.equals(iv1, iv2), "IVs should be different");
        assertEquals(decryptedPrivateKey1, decryptedPrivateKey2);
    }
}