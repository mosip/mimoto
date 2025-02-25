package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Service
public class UserMetadataService {

    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    public void updateOrInsertUserMetadata(String providerSubjectId, String identityProvider,
                                           String displayName, String profilePictureUrl,
                                           String email) {
        // Compute current time once
        Timestamp now = new Timestamp(System.currentTimeMillis());

        // Check if user exists
        Optional<UserMetadata> existingUser = userMetadataRepository.findByProviderSubjectId(providerSubjectId);

        if (existingUser.isPresent()) {
            // If user exists, update metadata
            updateUserMetadata(existingUser.get(), displayName, profilePictureUrl, email, now);
        } else {
            // If user does not exist, create new record
            createUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email, now);
        }
    }

    private void updateUserMetadata(UserMetadata userMetadata, String displayName, String profilePictureUrl,
                                    String email, Timestamp now) {
        boolean isUpdated = false;

        // Check and update fields if needed
        isUpdated |= updateField(userMetadata::getDisplayName, userMetadata::setDisplayName, displayName);
        isUpdated |= updateField(userMetadata::getProfilePictureUrl, userMetadata::setProfilePictureUrl, profilePictureUrl);
        isUpdated |= updateField(userMetadata::getEmail, userMetadata::setEmail, email);

        // Save the updated record
        if (isUpdated) {
            userMetadata.setUpdatedAt(now);
            userMetadataRepository.save(userMetadata);
        }
    }

    private boolean updateField(Supplier<String> getter, Consumer<String> setter, String newValue) {
        String decryptedValue = encryptionDecryptionUtil.decrypt(getter.get(), "user_pii", "", "");
        if (!decryptedValue.equals(newValue)) {
            setter.accept(encryptionDecryptionUtil.encrypt(newValue, "user_pii", "", ""));
            return true;
        }
        return false;
    }

    private void createUserMetadata(String providerSubjectId, String identityProvider, String displayName,
                                    String profilePictureUrl, String email, Timestamp now) {
        UserMetadata userMetadata = new UserMetadata();
        userMetadata.setProviderSubjectId(providerSubjectId);
        userMetadata.setIdentityProvider(identityProvider);
        userMetadata.setDisplayName(encryptionDecryptionUtil.encrypt(displayName, "user_pii", "", ""));
        userMetadata.setProfilePictureUrl(encryptionDecryptionUtil.encrypt(profilePictureUrl, "user_pii", "", ""));
        userMetadata.setEmail(encryptionDecryptionUtil.encrypt(email, "user_pii", "", ""));
        userMetadata.setCreatedAt(now);
        userMetadata.setUpdatedAt(now);

        userMetadataRepository.save(userMetadata); // Insert new record
    }
}
