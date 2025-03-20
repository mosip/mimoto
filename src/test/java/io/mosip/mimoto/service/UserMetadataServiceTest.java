package io.mosip.mimoto.service;

import io.mosip.mimoto.controller.SessionController;
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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = SessionController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
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
    public void shouldUpdateUserMetadataForSameProviderSubjectIdAndDifferentDisplayName() {
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
    public void shouldCreateNewUserMetadataIfUserRecordIsNotAvailableForReceivedProviderSubjectId() {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.empty());
        when(encryptionDecryptionUtil.encrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        when(userMetadataRepository.save(any(UserMetadata.class))).thenAnswer(invocation -> {
            UserMetadata savedUser = invocation.getArgument(0);
            savedUser.setId(userId);
            return savedUser;
        });

        storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        assertEquals(userId, storedUserId);
        verify(userMetadataRepository, times(1)).save(any(UserMetadata.class));
    }

    @Test
    public void shouldUpdateTheUpdatedFieldEvenIfNoChangesInMetadataObserved() throws InterruptedException {
        Timestamp timestampBeforeUpdate = userMetadata.getUpdatedAt();
        String updatedDisplayName = "Name 123";
        String updatedProfilePictureUrl = "http://profile.pic";
        String updatedEmail = "name.123@example.com";
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        when(encryptionDecryptionUtil.encrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        Thread.sleep(1);
        storedUserId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        ArgumentCaptor<UserMetadata> userMetadataCaptor = ArgumentCaptor.forClass(UserMetadata.class);
        verify(userMetadataRepository).save(userMetadataCaptor.capture());

        UserMetadata capturedUserMetadata = userMetadataCaptor.getValue();
        Timestamp after = capturedUserMetadata.getUpdatedAt();
        assertEquals(updatedDisplayName, capturedUserMetadata.getDisplayName());
        assertEquals(updatedProfilePictureUrl, capturedUserMetadata.getProfilePictureUrl());
        assertEquals(updatedEmail, capturedUserMetadata.getEmail());
        assertNotEquals(timestampBeforeUpdate, after);
        assertEquals(userId, storedUserId);
    }
}
