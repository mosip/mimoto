package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

import javax.validation.constraints.NotEmpty;
import java.util.List;

public class ProofTypesSupported {

    @NotEmpty
    @NotNull
    @JsonProperty("proof_signing_alg_values_supported")
    @SerializedName("proof_signing_alg_values_supported")
    private List<String> proofSigningAlgValuesSupported;
}
