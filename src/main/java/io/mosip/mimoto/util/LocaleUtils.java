package io.mosip.mimoto.util;

import java.util.Locale;

public class LocaleUtils {
    // Method to check if the localeString matches the 2-letter or 3-letter code
    public static boolean matchesLocale(String localeString1, String localeString2) {
        Locale locale1 = Locale.forLanguageTag(localeString1);

        // Check if localeString1 (from the object) matches either the 2-letter or 3-letter code of localeString2
        if (localeString1.length() == 2) {
            String iso3Language = locale1.getISO3Language(); // 3-letter code for locale1
            return localeString1.equals(localeString2) || iso3Language.equals(localeString2);
        } else if (localeString1.length() == 3) {
            String iso2Language = locale1.getLanguage(); // 2-letter code for locale1
            return localeString1.equals(localeString2) || iso2Language.equals(localeString2);
        }
        return false;
    }
}
