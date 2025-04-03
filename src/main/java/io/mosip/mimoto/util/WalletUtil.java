package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.KeyMetadata;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.repository.WalletRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Component
public class WalletUtil {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private CryptomanagerService cryptomanagerService;


    // Method to decrypt the wallet key using the PIN
    public String decryptWalletKey(String encryptedWalletKey, String pin) {
        // Prepare the request DTO
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setUserPin(pin);
        requestDto.setData(encryptedWalletKey);

        // Call the decryptWithPin method of CryptomanagerService
        CryptoWithPinResponseDto responseDto = cryptomanagerService.decryptWithPin(requestDto);

        // Return the decrypted wallet key
        return responseDto.getData();
    }

    public String createNewWallet(String userId, String walletName, String pin, KeyPair keyPair, SecretKey encryptionKey, String encryptionAlgorithm, String encryptionType) throws Exception {

        // Encrypt the private key with the encryption key
        String encryptedPrivateKey = EncryptionDecryptionUtil.encrypt(encryptionKey, keyPair.getPrivate().getEncoded());

        // Create wallet record
        String walletId = UUID.randomUUID().toString();
        Wallet newWallet = new Wallet();
        newWallet.setId(walletId);
        newWallet.setUserId(userId);

        // Encrypt the encryption key using the user's PIN before storing into database
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setUserPin(pin);
        String dataAsString = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
        requestDto.setData(dataAsString);
        String encryptedWalletKey = cryptomanagerService.encryptWithPin(requestDto).getData();

        // Set wallet metadata (encryption settings)
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setEncryptionAlgo(encryptionAlgorithm);
        walletMetadata.setEncryptionType(encryptionType);
        walletMetadata.setName(walletName);
        newWallet.setWalletMetadata(walletMetadata);

        // Set the wallet encryption key (encrypted wallet key)
        newWallet.setWalletKey(encryptedWalletKey);

        // Create the WalletKey entity (this will hold the actual keys)
        ProofSigningKey proofSigningKey = new ProofSigningKey();
        proofSigningKey.setId(UUID.randomUUID().toString());  // Generate a unique ID for the WalletKey
        proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        proofSigningKey.setSecretKey(encryptedPrivateKey);  // The private key is encrypted using the wallet's encryption key

        // Create and set the key metadata for the WalletKey
        KeyMetadata keyMetadata = new KeyMetadata();
        keyMetadata.setAlgorithmName(keyPair.getPublic().getAlgorithm());
        proofSigningKey.setKeyMetadata(keyMetadata);  // Associate the key metadata with the WalletKey

        // Associate the WalletKey with the Wallet
        proofSigningKey.setWallet(newWallet);  // Set the wallet for the key
        proofSigningKey.setCreatedAt(Instant.now());
        proofSigningKey.setUpdatedAt(Instant.now());

        // Add the WalletKey to the Wallet's list of keys
        List<ProofSigningKey> proofSigningKeys = new ArrayList<>();
        proofSigningKeys.add(proofSigningKey);
        newWallet.setProofSigningKeys(proofSigningKeys);

        // Save the wallet and its associated keys to the database
        walletRepository.save(newWallet);  // This will cascade and save the WalletKey as well

        return walletId;
    }


    // Default method for Ed25519 and AES
    public String createEd25519AlgoWallet(String userId, String walletName, String pin) throws Exception {
        SecretKey encryptionKey = EncryptionDecryptionUtil.generateEncryptionKey("AES", 256);
        KeyPair keyPair = EncryptionDecryptionUtil.generateKeyPair("Ed25519");
        return createNewWallet(userId, walletName, pin, keyPair, encryptionKey, "AES", "encryptWithPin");
    }

}
