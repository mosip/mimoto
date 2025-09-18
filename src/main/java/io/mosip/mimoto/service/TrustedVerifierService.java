package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.TrustedVerifierRequest;
import io.mosip.mimoto.dto.TrustedVerifierResponseDTO;

public interface TrustedVerifierService {

    TrustedVerifierResponseDTO addTrustedVerifier(String walletId, TrustedVerifierRequest trustedVerifierRequest);

}
