package io.mosip.mimoto.dto.mimoto;

import java.util.List;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Data
public class AppOTPRequestDTO {
    @NotNull
    private String individualId;
    @Pattern(regexp = "UIN|VID", message = "Only UIN or VID is allowed")
    private String individualIdType;
    @NotEmpty
    @NotNull
    private List<String> otpChannel;
    @NotNull
    private String transactionID;
}
