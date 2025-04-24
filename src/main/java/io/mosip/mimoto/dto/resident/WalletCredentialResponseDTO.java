package io.mosip.mimoto.dto.resident;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.core.io.InputStreamResource;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class WalletCredentialResponseDTO {

    @JsonProperty("file_content_stream")
    @Schema(description = "This is a PDF input stream containing the requested credential data in byte format")
    InputStreamResource fileContentStream;

    @JsonProperty("file_name")
    @Schema(description = " Name of the PDF file")
    String fileName;
}
