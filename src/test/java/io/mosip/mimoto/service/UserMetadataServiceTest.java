package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
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
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @InjectMocks
    private UserMetadataService userMetadataService;

    private String providerSubjectId, identityProvider, displayName, profilePictureUrl, email, userId, storedUserId;
    private Timestamp now;
    private UserMetadata userMetadata;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
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
        userMetadata.setDisplayName(displayName);
        userMetadata.setProfilePictureUrl(profilePictureUrl);
        userMetadata.setEmail(email);
        userMetadata.setCreatedAt(now);
        userMetadata.setUpdatedAt(now);
    }

    @Test
    public void shouldUpdateUserMetadataForSameProviderSubjectIdAndSameIdentityProviderButWithDifferentDisplayName() {
        String updatedDisplayName = "Name 124";
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        when(encryptionDecryptionUtil.encrypt(anyString(), any(), any(), any())).thenReturn(updatedDisplayName, profilePictureUrl, email);

        storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, updatedDisplayName, profilePictureUrl, email);

        assertEquals(userId, storedUserId);
        assertEquals(userMetadata.getDisplayName(), updatedDisplayName);
        verify(userMetadataRepository, times(1)).save(userMetadata);
    }

    @Test
    public void shouldCreateNewUserMetadataForSameProviderSubjectIdAndDifferentIdentityProvider() {
        String identityProvider = "facebook";
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.empty());
        when(encryptionDecryptionUtil.encrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        when(userMetadataRepository.save(any(UserMetadata.class))).thenReturn(userMetadata);

        userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());

        UserMetadata capturedUserMetadata = userMetadataCaptor.getValue();
        String storedUserId = capturedUserMetadata.getId();
        assertNotEquals(userId, storedUserId);
    }

    @Test
    public void shouldCreateNewUserMetadataForDifferentProviderSubjectIdAndSameIdentityProvider() {
        String providerSubjectId = "provider124";
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.empty());
        when(encryptionDecryptionUtil.encrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        when(userMetadataRepository.save(any(UserMetadata.class))).thenReturn(userMetadata);

        userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());

        UserMetadata capturedUserMetadata = userMetadataCaptor.getValue();
        String storedUserId = capturedUserMetadata.getId();
        assertNotEquals(userId, storedUserId);
    }

    @Test
    public void shouldNotCreateNewUserMetadataForSameProviderSubjectIdAndSameIdentityProvider() {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);

        userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        verify(userMetadataRepository,times(0)).save(any(UserMetadata.class));
    }
}
