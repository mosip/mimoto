package io.mosip.mimoto.util;

import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.model.SigningAlgorithm;
import io.mosip.mimoto.repository.WalletRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class WalletUtil {
    private static final String SESSION_WALLET_KEY = "wallet_key";
    private static final String SESSION_WALLET_ID = "wallet_id";

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    public String decryptWalletKey(String encryptedWalletKey, String pin) {
        return encryptionDecryptionUtil.decryptWithPin(encryptedWalletKey, pin);
    }

    public String createWallet(String userId, String walletName, String pin) throws Exception {
        SecretKey encryptionKey = KeyGenerationUtil.generateEncryptionKey("AES", 256);
        return saveWallet(userId, walletName, pin, encryptionKey, "AES", "encryptWithPin");
    }

    public String saveWallet(String userId, String walletName, String walletPin, SecretKey encryptionKey, String encryptionAlgorithm, String encryptionType) throws Exception {

        String walletId = UUID.randomUUID().toString();
        WalletMetadata walletMetadata = createWalletMetadata(walletName, encryptionAlgorithm, encryptionType);
        String walletKey = encryptionDecryptionUtil.encryptKeyWithPin(encryptionKey, walletPin);
        Wallet newWallet = Wallet.builder()
                .id(walletId)
                .userId(userId)
                .walletMetadata(walletMetadata)
                .walletKey(walletKey)
                .build();

        List<ProofSigningKey> proofSigningKeys = createProofSigningKeys(encryptionKey, newWallet);
        newWallet.setProofSigningKeys(proofSigningKeys);

        walletRepository.save(newWallet);
        return walletId;
    }

    private WalletMetadata createWalletMetadata(String walletName, String encryptionAlgorithm, String encryptionType) {
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setEncryptionAlgo(encryptionAlgorithm);
        walletMetadata.setEncryptionType(encryptionType);
        walletMetadata.setName(walletName);
        return walletMetadata;
    }

    private List<ProofSigningKey> createProofSigningKeys(SecretKey encryptionKey, Wallet wallet) throws Exception {
        List<ProofSigningKey> proofSigningKeys = new ArrayList<>();
        List<SigningAlgorithm> algorithms = List.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.ES256K, SigningAlgorithm.ED25519);
        for (SigningAlgorithm algorithm : algorithms) {
            ProofSigningKey signingKey = ProofSigningKeyFactory.createProofSigningKey(algorithm);
            signingKey.setWallet(wallet);
            signingKey.setEncryptedSecretKey(encryptionDecryptionUtil.encryptWithAES(encryptionKey,
                    signingKey.getSecretKey().getEncoded()));
            proofSigningKeys.add(signingKey);
        }
        return proofSigningKeys;
    }

    public static String getSessionWalletKey(HttpSession session) {
        Object key = session.getAttribute(SESSION_WALLET_KEY);
        if (key == null) throw new RuntimeException("Wallet Key is missing in session");
        return key.toString();
    }

    public static void validateWalletId(HttpSession session, String walletIdFromRequest) {
        Object sessionWalletId = session.getAttribute(SESSION_WALLET_ID);
        if (sessionWalletId == null) throw new RuntimeException("Wallet Id is missing in session");

        String walletIdInSession = sessionWalletId.toString();
        if (!walletIdInSession.equals(walletIdFromRequest)) {
            throw new RuntimeException("Invalid Wallet Id. Session and request Wallet Id do not match");
        }
    }
}