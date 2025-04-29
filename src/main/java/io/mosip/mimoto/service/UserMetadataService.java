package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.Optional;
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

    public String updateOrInsertUserMetadata(String providerSubjectId, String identityProvider,
                                             String displayName, String profilePictureUrl, String email)
            throws EncryptionException, DecryptionException {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        Optional<UserMetadata> existingUser = repository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider);
        if (existingUser.isPresent()) {
            return updateUser(existingUser.get(), displayName, profilePictureUrl, email, now);
        } else {
            return createUser(providerSubjectId, identityProvider, displayName, profilePictureUrl, email, now);
        }
    }

    private String updateUser(UserMetadata user, String displayName, String profilePictureUrl, String email, Timestamp now)
            throws EncryptionException, DecryptionException {
        boolean updated = updateIfChanged(user::getDisplayName, user::setDisplayName, displayName)
                || updateIfChanged(user::getProfilePictureUrl, user::setProfilePictureUrl, profilePictureUrl)
                || updateIfChanged(user::getEmail, user::setEmail, email);
        if (updated) {
            user.setUpdatedAt(now);
            repository.save(user);
        }
        return user.getId();
    }

    private boolean updateIfChanged(Supplier<String> getter, Consumer<String> setter, String newValue)
            throws EncryptionException, DecryptionException {
        String current = encryptionService.decrypt(getter.get());
        if (!current.equals(newValue)) {
            setter.accept(encryptionService.encrypt(newValue));
            return true;
        }
        return false;
    }

    private String createUser(String providerSubjectId, String identityProvider, String displayName,
                              String profilePictureUrl, String email, Timestamp now)
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
