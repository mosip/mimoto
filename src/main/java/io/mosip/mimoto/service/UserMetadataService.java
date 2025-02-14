package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.Optional;

@Service
public class UserMetadataService {

    private final UserMetadataRepository userMetadataRepository;

    @Autowired
    public UserMetadataService(UserMetadataRepository userMetadataRepository) {
        this.userMetadataRepository = userMetadataRepository;
    }

    public void updateOrInsertUserMetadata(String providerSubjectId, String identityProvider,
                                           String displayName, String profilePictureUrl,
                                           String email) {
        // Check if user exists
        Optional<UserMetadata> existingUser = userMetadataRepository.findByProviderSubjectId(providerSubjectId);

        UserMetadata userMetadata;

        if (existingUser.isPresent()) {
            userMetadata = existingUser.get();

            // Check if any attributes need to be updated
            boolean isUpdated = false;
            Timestamp now = new Timestamp(System.currentTimeMillis());

            if (!userMetadata.getDisplayName().equals(displayName)) {
                userMetadata.setDisplayName(displayName);
                isUpdated = true;
            }
            if (!userMetadata.getProfilePictureUrl().equals(profilePictureUrl)) {
                userMetadata.setProfilePictureUrl(profilePictureUrl);
                isUpdated = true;
            }
            if (!userMetadata.getEmail().equals(email)) {
                userMetadata.setEmail(email);
                isUpdated = true;
            }

            if (isUpdated) {
                userMetadata.setUpdatedAt(now);
                userMetadataRepository.save(userMetadata);  // Update record
            }

        } else {
            // If the user does not exist, create a new record
            userMetadata = new UserMetadata();
            userMetadata.setProviderSubjectId(providerSubjectId);
            userMetadata.setIdentityProvider(identityProvider);
            userMetadata.setDisplayName(displayName);
            userMetadata.setProfilePictureUrl(profilePictureUrl);
            userMetadata.setEmail(email);
            userMetadata.setCreatedAt(new Timestamp(System.currentTimeMillis()));
            userMetadata.setUpdatedAt(new Timestamp(System.currentTimeMillis()));

            userMetadataRepository.save(userMetadata);  // Insert new record
        }
    }
}

