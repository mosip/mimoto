package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.model.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Service
public class UserMetadataService {
    private final UserMetadataRepository repository;
    private final EncryptionService encryptionService;

    @Autowired
    public UserMetadataService(UserMetadataRepository repository, EncryptionService encryptionService) {
        this.repository = repository;
        this.encryptionService = encryptionService;
    }

    public UserMetadata getUserMetadata(String providerSubjectId, String identityProvider)
            throws DecryptionException {
        return repository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)
                .map(user -> {
                    try {
                        UserMetadata decryptedUser = new UserMetadata();
                        decryptedUser.setId(user.getId());
                        decryptedUser.setProviderSubjectId(user.getProviderSubjectId());
                        decryptedUser.setIdentityProvider(user.getIdentityProvider());

                        decryptedUser.setDisplayName(encryptionService.decrypt(user.getDisplayName()));
                        decryptedUser.setProfilePictureUrl(encryptionService.decrypt(user.getProfilePictureUrl()));
                        decryptedUser.setEmail(encryptionService.decrypt(user.getEmail()));

                        return decryptedUser;
                    } catch (DecryptionException e) {
                        throw new RuntimeException("Failed to decrypt user metadata", e);
                    }
                })
                .orElse(null);
    }

    public String updateOrCreateUserMetadata(String providerSubjectId, String identityProvider,
                                             String displayName, String profilePictureUrl, String email)
            throws EncryptionException, DecryptionException {
        Instant now = Instant.now();
        UserMetadata existingUser = getUserMetadata(providerSubjectId, identityProvider);
        if (null != existingUser) {
            return updateUser(existingUser, displayName, profilePictureUrl, email, now);
        } else {
            return createUser(providerSubjectId, identityProvider, displayName, profilePictureUrl, email, now);
        }
    }

    private String updateUser(UserMetadata user, String displayName, String profilePictureUrl, String email, Instant now)
            throws EncryptionException {
        boolean updated = updateIfChanged(user::getDisplayName, user::setDisplayName, displayName);
        updated = updateIfChanged(user::getProfilePictureUrl, user::setProfilePictureUrl, profilePictureUrl) || updated;
        updated = updateIfChanged(user::getEmail, user::setEmail, email) || updated;

        if (updated) {
            user.setUpdatedAt(now);
            repository.save(user);
        }
        return user.getId();
    }

    private boolean updateIfChanged(Supplier<String> getter, Consumer<String> setter, String newValue)
            throws EncryptionException {
        String current = getter.get();
        setter.accept(encryptionService.encrypt(newValue));
        return !current.equals(newValue);
    }

    private String createUser(String providerSubjectId, String identityProvider, String displayName,
                              String profilePictureUrl, String email, Instant now)
            throws EncryptionException {
        UserMetadata user = new UserMetadata();
        user.setId(UUID.randomUUID().toString());
        user.setProviderSubjectId(providerSubjectId);
        user.setIdentityProvider(identityProvider);
        user.setDisplayName(encryptionService.encrypt(displayName));
        user.setProfilePictureUrl(encryptionService.encrypt(profilePictureUrl));
        user.setEmail(encryptionService.encrypt(email));
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return repository.save(user).getId();
    }
}
