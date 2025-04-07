package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dbentity.ProofSigningKey;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.SigningAlgorithm;
import io.mosip.mimoto.repository.ProofSigningKeyRepository;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.*;

@Slf4j
@Service
public class CredentialUtilService {
    @Autowired
    IdpService idpService;

    @Autowired
    RestTemplate restTemplate;

    @Autowired
    IssuersService issuersService;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    JoseUtil joseUtil;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private ProofSigningKeyRepository proofSigningKeyRepository;

    CredentialsVerifier credentialsVerifier;

    @PostConstruct
    public void init() {
        credentialsVerifier = new CredentialsVerifier();
    }

    @Autowired
    ObjectMapper objectMapper;

    public TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        String tokenEndpoint = idpService.getTokenEndpoint(credentialIssuerConfiguration);
        HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO, tokenEndpoint);
        TokenResponseDTO response = restTemplate.postForObject(tokenEndpoint, request, TokenResponseDTO.class);
        if (response == null) {
            throw new IdpException("Exception occurred while performing the authorization");
        }
        return response;
    }

    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException {
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        log.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null) throw new RuntimeException("VC Credential Issue API not accessible");
        return vcCredentialResponse;
    }

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken, String walletId, String base64EncodedWalletKey,Boolean isLoginFlow) throws Exception {
        String jwt;

        Map<String, ProofTypesSupported> proofTypesSupported = credentialsSupportedResponse.getProofTypesSupported();
        SigningAlgorithm algorithm;
        if (proofTypesSupported.containsKey("jwt")) {
            algorithm = SigningAlgorithm.fromString(proofTypesSupported.get("jwt").getProofSigningAlgValuesSupported().get(0));
        } else {
            algorithm = SigningAlgorithm.RS256;
        }

        if (!isLoginFlow) {
            jwt = joseUtil.generateJwt(credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        } else {
            Optional<ProofSigningKey> proofSigningKey = proofSigningKeyRepository.findByWalletIdAndAlgorithm(walletId, algorithm.name());
            byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
            SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
            byte[] publicKeyBytes = Base64.getDecoder().decode(proofSigningKey.get().getPublicKey());
            byte[] privateKeyInBytes = encryptionDecryptionUtil.decryptWithAES(walletKey, proofSigningKey.get().getEncryptedSecretKey());
            jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(algorithm, credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken, publicKeyBytes, privateKeyInBytes);
        }

        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public Boolean verifyCredential(VCCredentialResponse vcCredentialResponse) throws VCVerificationException, JsonProcessingException {
        log.info("Initiated the VC Verification : Started");
        String credentialString = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());
        VerificationResult verificationResult = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        if (!verificationResult.getVerificationStatus()) {
            throw new VCVerificationException(verificationResult.getVerificationErrorCode().toLowerCase(), verificationResult.getVerificationMessage());
        }
        log.info("Completed the VC Verification : Completed -> result : " + verificationResult);
        return true;
    }
}

