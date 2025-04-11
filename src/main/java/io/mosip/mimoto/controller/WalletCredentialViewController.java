package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.DatabaseConnectionException;
import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import io.mosip.mimoto.service.impl.WalletCredentialViewServiceImpl;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import static io.mosip.mimoto.exception.PlatformErrorMessages.*;

@RestController
@RequestMapping(value = "/credentials")
@Slf4j
public class WalletCredentialViewController {

    @Autowired
    private WalletCredentialViewServiceImpl walletCredentialViewServiceImpl;

    @GetMapping("/{credentialId}")
    public ResponseEntity<?> getVerifiableCredential(@PathVariable("credentialId") String credentialId, @RequestParam("locale") String locale, @RequestParam(value = "action", defaultValue = "inline") String action, HttpSession httpSession) {
        try {
            Object walletKeyObj = httpSession.getAttribute("wallet_key");
            if (walletKeyObj == null) {
                throw new RuntimeException("Wallet key is missing in session");
            }
            String base64EncodedWalletKey = walletKeyObj.toString();
            WalletCredentialResponseDTO walletCredentialResponseDTO = walletCredentialViewServiceImpl.fetchVerifiableCredential(
                    credentialId, base64EncodedWalletKey, locale);

            String dispositionType = "download".equalsIgnoreCase(action) ? "attachment" : "inline";
            String contentDisposition = String.format("%s; filename=\"%s\"",
                    dispositionType, walletCredentialResponseDTO.getFileName());

            return ResponseEntity.ok()
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION)
                    .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(walletCredentialResponseDTO.getFileContentStream());

        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to fetch the Verifiable Credential:", exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.VERIFIABLECREDENTIAL, DatabaseOperation.FETCHING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), connectionException.getStatus(), MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Error occurred while fetching the Verifiable Credential : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, CREDENTIAL_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
}
