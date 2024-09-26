package io.mosip.mimoto.dto;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonAlias;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Instantiates a new error DTO.
 *
 * @param errorcode the errorcode
 * @param message   the message
 *
 * @author Rishabh Keshari
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ErrorDTO implements Serializable {

    private static final long serialVersionUID = 2452990684776944908L;

    /** The errorcode. */
    private String errorCode;

    /** The message. */
    @JsonAlias("message")
    private String errorMessage;
}
