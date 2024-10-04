package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

@Data
public class BindingOtpInnerReqDto {

    @NotNull
    @Schema(description = "Individual ID For Binding OTP")
    private String individualId;
    @NotNull
    @NotEmpty
    @Schema(description = "Notifying medium in which OTP is sent", allowableValues = {"PHONE", "EMAIL"})
    private List<String> otpChannels;
}
