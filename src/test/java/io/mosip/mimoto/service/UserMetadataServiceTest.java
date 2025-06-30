package io.mosip.mimoto.service;

import io.mosip.mimoto.model.UserMetadata;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class UserMetadataServiceTest {

    @Mock
    private UserMetadataRepository userMetadataRepository;

    @Mock
    private EncryptionService encryptionService;

    @InjectMocks
    private UserMetadataService userMetadataService;

    private String providerSubjectId, identityProvider, displayName, profilePictureUrl, email, userId;
    private Timestamp now;
    private UserMetadata userMetadata;

    @Before
    public void setUp() {
        providerSubjectId = "provider123";
        identityProvider = "google";
        displayName = "Name 123";
        profilePictureUrl = "http://profile.pic";
        email = "name.123@example.com";
        now = new Timestamp(System.currentTimeMillis());
        userId = UUID.randomUUID().toString();

        userMetadata = new UserMetadata();
        userMetadata.setId(userId);
        userMetadata.setProviderSubjectId(providerSubjectId);
        userMetadata.setIdentityProvider(identityProvider);
        userMetadata.setDisplayName("encryptedDisplayName");
        userMetadata.setProfilePictureUrl("encryptedProfilePictureUrl");
        userMetadata.setEmail("encryptedEmail");
        userMetadata.setCreatedAt(now);
        userMetadata.setUpdatedAt(now);
    }

    @Test
    public void shouldUpdateUserMetadataForSameProviderSubjectIdAndSameIdentityProviderButWithDifferentDisplayName() throws DecryptionException, EncryptionException {
        String updatedDisplayName = "Name 124";
        String encryptedUpdatedDisplayName = "encryptedUpdatedDisplayName";

        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt("encryptedDisplayName")).thenReturn(displayName);
        when(encryptionService.encrypt(updatedDisplayName)).thenReturn(encryptedUpdatedDisplayName);
        when(encryptionService.decrypt("encryptedProfilePictureUrl")).thenReturn(profilePictureUrl);
        when(encryptionService.encrypt(profilePictureUrl)).thenReturn("encryptedProfilePictureUrl");
        when(encryptionService.decrypt("encryptedEmail")).thenReturn(email);
        when(encryptionService.encrypt(email)).thenReturn("encryptedEmail");
        when(userMetadataRepository.save(any(UserMetadata.class))).thenReturn(userMetadata);

        String storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, updatedDisplayName, profilePictureUrl, email);

        assertEquals(userId, storedUserId);
        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());
        UserMetadata savedUserMetadata = userMetadataCaptor.getValue();
        assertEquals(encryptedUpdatedDisplayName, savedUserMetadata.getDisplayName());
        assertEquals("encryptedProfilePictureUrl", savedUserMetadata.getProfilePictureUrl());
        assertEquals("encryptedEmail", savedUserMetadata.getEmail());
        verify(encryptionService).decrypt("encryptedDisplayName");
        verify(encryptionService).encrypt(updatedDisplayName);
    }

    @Test
    public void shouldCreateNewUserMetadataForSameProviderSubjectIdAndDifferentIdentityProvider() throws DecryptionException, EncryptionException {
        String newIdentityProvider = "facebook";
        String newUserId = UUID.randomUUID().toString();
        UserMetadata newUserMetadata = new UserMetadata();
        newUserMetadata.setId(newUserId);
        newUserMetadata.setProviderSubjectId(providerSubjectId);
        newUserMetadata.setIdentityProvider(newIdentityProvider);
        newUserMetadata.setDisplayName("encryptedDisplayName");
        newUserMetadata.setProfilePictureUrl("encryptedProfilePictureUrl");
        newUserMetadata.setEmail("encryptedEmail");
        newUserMetadata.setCreatedAt(now);
        newUserMetadata.setUpdatedAt(now);

        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, newIdentityProvider)).thenReturn(Optional.empty());
        when(encryptionService.encrypt(displayName)).thenReturn("encryptedDisplayName");
        when(encryptionService.encrypt(profilePictureUrl)).thenReturn("encryptedProfilePictureUrl");
        when(encryptionService.encrypt(email)).thenReturn("encryptedEmail");
        when(userMetadataRepository.save(any(UserMetadata.class))).thenReturn(newUserMetadata);

        String storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, newIdentityProvider, displayName, profilePictureUrl, email);

        assertEquals(newUserId, storedUserId);
        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());
        UserMetadata capturedUserMetadata = userMetadataCaptor.getValue();
        assertEquals(providerSubjectId, capturedUserMetadata.getProviderSubjectId());
        assertEquals(newIdentityProvider, capturedUserMetadata.getIdentityProvider());
        assertEquals("encryptedDisplayName", capturedUserMetadata.getDisplayName());
        assertEquals("encryptedProfilePictureUrl", capturedUserMetadata.getProfilePictureUrl());
        assertEquals("encryptedEmail", capturedUserMetadata.getEmail());
        verify(encryptionService, times(3)).encrypt(anyString());
    }

    @Test
    public void shouldCreateNewUserMetadataForDifferentProviderSubjectIdAndSameIdentityProvider() throws DecryptionException, EncryptionException {
        String newProviderSubjectId = "provider124";
        String newUserId = UUID.randomUUID().toString();
        UserMetadata newUserMetadata = new UserMetadata();
        newUserMetadata.setId(newUserId);
        newUserMetadata.setProviderSubjectId(newProviderSubjectId);
        newUserMetadata.setIdentityProvider(identityProvider);
        newUserMetadata.setDisplayName("encryptedDisplayName");
        newUserMetadata.setProfilePictureUrl("encryptedProfilePictureUrl");
        newUserMetadata.setEmail("encryptedEmail");
        newUserMetadata.setCreatedAt(now);
        newUserMetadata.setUpdatedAt(now);

        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(newProviderSubjectId, identityProvider)).thenReturn(Optional.empty());
        when(encryptionService.encrypt(displayName)).thenReturn("encryptedDisplayName");
        when(encryptionService.encrypt(profilePictureUrl)).thenReturn("encryptedProfilePictureUrl");
        when(encryptionService.encrypt(email)).thenReturn("encryptedEmail");
        when(userMetadataRepository.save(any(UserMetadata.class))).thenReturn(newUserMetadata);

        String storedUserId = userMetadataService.updateOrInsertUserMetadata(newProviderSubjectId, identityProvider, displayName, profilePictureUrl, email);

        assertEquals(newUserId, storedUserId);
        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());
        UserMetadata capturedUserMetadata = userMetadataCaptor.getValue();
        assertEquals(newProviderSubjectId, capturedUserMetadata.getProviderSubjectId());
        assertEquals(identityProvider, capturedUserMetadata.getIdentityProvider());
        assertEquals("encryptedDisplayName", capturedUserMetadata.getDisplayName());
        assertEquals("encryptedProfilePictureUrl", capturedUserMetadata.getProfilePictureUrl());
        assertEquals("encryptedEmail", capturedUserMetadata.getEmail());
        verify(encryptionService, times(3)).encrypt(anyString());
    }

    @Test
    public void shouldNotCreateNewUserMetadataForSameProviderSubjectIdAndSameIdentityProvider() throws DecryptionException, EncryptionException {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt(userMetadata.getDisplayName())).thenReturn(displayName);
        when(encryptionService.decrypt(userMetadata.getProfilePictureUrl())).thenReturn(profilePictureUrl);
        when(encryptionService.decrypt(userMetadata.getEmail())).thenReturn(email);

        String storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        assertEquals(userId, storedUserId);
        verify(userMetadataRepository, times(0)).save(any(UserMetadata.class));
        verify(encryptionService).decrypt(userMetadata.getDisplayName());
        verify(encryptionService).decrypt(userMetadata.getProfilePictureUrl());
        verify(encryptionService).decrypt(userMetadata.getEmail());
        verify(encryptionService, times(3)).encrypt(anyString());
    }
}