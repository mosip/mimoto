package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;

import java.util.Map;

public class ProofTypesSupported {
    @SerializedName("proof_signing_alg_values_supported")
    @JsonProperty("proof_signing_alg_values_supported")
    private Map<String,ProofSigningAlgValuesSupported> proofSigningAlgValuesSupported;
}
