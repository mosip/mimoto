package io.mosip.mimoto.util;

import io.mosip.mimoto.dbentity.KeyMetadata;
import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.SigningAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.ENCRYPTION_FAILED;

@Slf4j
public class ProofSigningKeyFactory {

    public static ProofSigningKey createProofSigningKey(SigningAlgorithm algorithm)  {
        try {
            KeyPair keyPair = KeyGenerationUtil.generateKeyPair(algorithm);

            KeyMetadata keyMetadata = new KeyMetadata();
            keyMetadata.setAlgorithmName(algorithm.name());

            ProofSigningKey proofSigningKey = new ProofSigningKey();
            proofSigningKey.setId(UUID.randomUUID().toString());
            proofSigningKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            proofSigningKey.setSecretKey(keyPair.getPrivate());
            proofSigningKey.setKeyMetadata(keyMetadata);
            proofSigningKey.setCreatedAt(Instant.now());
            proofSigningKey.setUpdatedAt(Instant.now());

            return proofSigningKey;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            log.error("Error while generating key",e);
            throw new KeyGenerationException(ENCRYPTION_FAILED.getErrorCode(), "Failed to generate proof signing key for algorithm: " + algorithm);
        }
    }
}
