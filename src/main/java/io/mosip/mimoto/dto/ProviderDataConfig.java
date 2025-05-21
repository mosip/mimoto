package io.mosip.mimoto.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The ProviderDataConfig class represents a configuration for provider data attributes.
 * It contains fields for various attributes such as username, name, email, picture, and phone number.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProviderDataConfig {
    private String userNameAttribute;
    private String nameAttribute;
    private String emailAttribute;
    private String pictureAttribute;
    private String phoneNumberAttribute;
}
