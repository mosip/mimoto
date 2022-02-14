package io.mosip.residentapp.dto.mosip;

import java.util.List;

import lombok.Data;

@Data
public class IdResponseDTO {

    /** The entity. */
    private String entity;

    /** The identity. */
    private Object identity;

    private List<Documents> documents;

    /** The status. */
    private String status;
}
