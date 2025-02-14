package io.mosip.mimoto.util;

import java.util.Locale;

public class LocaleUtils {
    // Method to convert the input locale strings into 3-letter codes and compare
    public static boolean matchesLocale(String localeString1, String localeString2) {
        String locale1Iso3Language = Locale.forLanguageTag(localeString1).getISO3Language(); // 3-letter code for locale1
        String locale2Iso3Language = Locale.forLanguageTag(localeString2).getISO3Language(); // 3-letter code for locale2

        return locale1Iso3Language.equals(locale2Iso3Language);
    }
}
