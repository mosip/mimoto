package io.mosip.mimoto.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.MediaType;
import java.io.ByteArrayInputStream;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialResponse {
    private ByteArrayInputStream content;
    private MediaType mediaType;
}