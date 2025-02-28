package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialDisplayResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public class LocaleUtils {
    // Method to convert the input locale strings into 3-letter codes and compare
    public static boolean matchesLocale(String localeString1, String localeString2) {
        if(localeString1 == null || localeString2 == null){
            return false;
        }

        String locale1Iso3Language = Locale.forLanguageTag(localeString1).getISO3Language(); // 3-letter code for locale1
        String locale2Iso3Language = Locale.forLanguageTag(localeString2).getISO3Language(); // 3-letter code for locale2

        return locale1Iso3Language.equals(locale2Iso3Language);
    }

    public static String resolveLocaleWithFallback(Map<String, CredentialDisplayResponseDto> credentialSubject, String locale) {
        String selectedLocale = null;

        // Iterate through the credentials to check if any display object supports the requested locale
        for (String VCProperty : credentialSubject.keySet()) {
            List<CredentialIssuerDisplayResponse> displayList = credentialSubject.get(VCProperty).getDisplay();
            // Check if any display object supports the requested locale
            Optional<CredentialIssuerDisplayResponse> filteredResponse = displayList.stream()
                    .filter(obj -> matchesLocale(obj.getLocale(), locale))
                    .findFirst();
            if (filteredResponse.isPresent()) {
                selectedLocale = filteredResponse.get().getLocale();
                break; // Break once a matching record is found
            }
        }
        // If no matching locale is found, use the locale of the first display object
        if (selectedLocale == null) {
            // Fall back to the locale of the first display object if no matching locale is found
            for (String VCProperty : credentialSubject.keySet()) {
                List<CredentialIssuerDisplayResponse> displayList = credentialSubject.get(VCProperty).getDisplay();
                if (displayList != null && !displayList.isEmpty()) {
                    // Get the locale of the first display object in the list
                    selectedLocale = displayList.get(0).getLocale();
                    break; // Use the first locale and exit the loop
                }
            }
        }
        return selectedLocale;
    }

}
