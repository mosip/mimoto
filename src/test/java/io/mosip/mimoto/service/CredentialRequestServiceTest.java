package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.impl.CredentialRequestServiceImpl;
import io.mosip.mimoto.util.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.mockito.ArgumentCaptor;

import java.util.Collections;
import java.util.List;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CredentialRequestServiceImpl.class})
@TestPropertySource(locations = "classpath:application-test.properties")
public class CredentialRequestServiceTest {
    @Autowired
    private CredentialRequestServiceImpl credentialRequestServiceImpl;

    @MockBean
    private ProofSigningKeyRepository proofSigningKeyRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    JoseUtil joseUtil;

    private final MockedStatic<KeyGenerationUtil> keyGenerationUtilMockedStatic = Mockito.mockStatic(KeyGenerationUtil.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));

    IssuerDTO issuerDTO;
    String issuerId;

    @Before
    public void setUp() {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
    }

    @After
    public void tearDown() {
        if(keyGenerationUtilMockedStatic != null) {
            keyGenerationUtilMockedStatic.close();
        }
    }

    @Test
    public void shouldHandleNullContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.getCredentialDefinition().setContext(null);

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");

        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().getFirst());
    }

    @Test
    public void shouldHandleEmptyContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set an empty list as context
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of());

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().getFirst());
    }


    @Test
    public void shouldHandleExistingContextWithSpecificValue() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set context with a specific value
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of("https://www.w3.org/ns/credentials/v2"));

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");

        VCCredentialRequest result = credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/ns/credentials/v2", result.getCredentialDefinition().getContext().getFirst());
    }

    @Test
    public void shouldReturnFallbackAlgorithmWhenJwtProofTypeOfProofTypesSupportedIsNull() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", null);


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> KeyGenerationUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }

    @Test
    public void shouldReturnFallbackAlgorithmWhenJwtProofTypeOfProofTypesSupportedIsEmpty() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(Collections.emptyList());
        credentialsSupportedResponse.getProofTypesSupported().put("jwt", proofTypesSupported);

        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> KeyGenerationUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }

    @Test
    public void shouldUseHighestPriorityAlgorithmInPredefinedSigningAlgoPrioritySetWhichIsAlsoSupportedByIssuer() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        credentialsSupportedResponse.getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(List.of("es256k"));


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> KeyGenerationUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ES256K, capturedAlgorithm);
    }

    @Test
    public void shouldUseFallbackPrioritySigningAlgorithmIfNoneOfIssuerSupportedAlgoAreSupportedByMimto() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");
        credentialsSupportedResponse.getProofTypesSupported().get("jwt").setProofSigningAlgValuesSupported(List.of("ps256"));


        credentialRequestServiceImpl.buildRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-cnonce",
                "walletId",
                "walletKey",
                false
        );


        ArgumentCaptor<SigningAlgorithm> argumentCaptor = ArgumentCaptor.forClass(SigningAlgorithm.class);
        keyGenerationUtilMockedStatic.verify(() -> KeyGenerationUtil.generateKeyPair(argumentCaptor.capture()));
        SigningAlgorithm capturedAlgorithm = argumentCaptor.getValue();
        assertEquals(SigningAlgorithm.ED25519, capturedAlgorithm);
    }
}