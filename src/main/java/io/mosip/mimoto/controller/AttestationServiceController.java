package io.mosip.mimoto.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.mimoto.AttestationStatement;
import io.mosip.mimoto.dto.mimoto.GenericResponseDTO;
import io.mosip.mimoto.util.AttestationOfflineVerify;
import io.mosip.mimoto.util.AttestationOnlineVerify;
import io.mosip.mimoto.util.LoggerUtil;

@RestController
@RequestMapping(value = "/safetynet")
public class AttestationServiceController {

    private final Logger logger = LoggerUtil.getLogger(AttestationServiceController.class);

    @Autowired
    AttestationOfflineVerify attestationOfflineVerify;

    @Autowired
    AttestationOnlineVerify attestationOnlineVerify;

    /**
     * Safetynet attestation verify using offline method.
     *
     * @param attestation
     * @return
     */
    @PostMapping(path = "/offline/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> processOffline(@RequestBody String attestation)
    {
        try {
            AttestationStatement attestationStatement = attestationOfflineVerify.parseAndVerify(attestation);
            return new ResponseEntity<>(attestationStatement, HttpStatus.OK);
        } catch (Exception e) {
            GenericResponseDTO responseDTO = new GenericResponseDTO();
            responseDTO.setStatus("Error");
            responseDTO.setMessage(e.getMessage());
            
            return new ResponseEntity<>(responseDTO, HttpStatus.OK);
        }
    }

    /**
     * Safetynet attestation verify using online method with Google API.
     *
     * @param attestation
     * @return
     */
    @PostMapping(path = "/online/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> processOnline(@RequestBody String attestation)
    {
        try {
            AttestationStatement attestationStatement = attestationOnlineVerify.parseAndVerify(attestation);
            return new ResponseEntity<>(attestationStatement, HttpStatus.OK);
        } catch (Exception e) {
            GenericResponseDTO responseDTO = new GenericResponseDTO();
            responseDTO.setStatus("Error");
            responseDTO.setMessage(e.getMessage());
            
            return new ResponseEntity<>(responseDTO, HttpStatus.OK);
        }
    }
}
