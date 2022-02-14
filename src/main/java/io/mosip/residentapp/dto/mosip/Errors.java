package io.mosip.residentapp.dto.mosip;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class Errors {
    String errorCode;
    String message;
}