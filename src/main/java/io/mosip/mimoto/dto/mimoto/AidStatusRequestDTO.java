package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

@Data
public class AidStatusRequestDTO {

	private String aid;
	private String otp;
	private String transactionID;
	
}
