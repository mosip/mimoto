package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

import java.io.Serializable;

/**
 * This class will provide values to hold uin,vid and vidStatus
 * 
 * @author Prem Kumar
 *
 */
@Data
public class VidResDTO implements Serializable {

    /** The Value Of UIN in Decrypted value */
    @JsonProperty("UIN")
    private String uin;

    /** The Value to hold vid */
    @JsonProperty("VID")
    private String vid;

    /** The Value to hold vidStatus */
    private String vidStatus;

    /** The Value to hold updatedVid */
    private VidResDTO restoredVid;

}