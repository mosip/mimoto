package io.mosip.mimoto.constant;

public enum CredentialFormat {
    VC_SD_JWT("vc+sd-jwt"),
    DC_SD_JWT("dc+sd-jwt"),
    LDP_VC("ldp_vc");

    private final String format;

    CredentialFormat(String format) {
        this.format = format;
    }

    public String getFormat() {
        return format;
    }

    public static CredentialFormat fromString(String format) {
        for (CredentialFormat cf : CredentialFormat.values()) {
            if (cf.format.equalsIgnoreCase(format)) {
                return cf;
            }
        }
        throw new IllegalArgumentException("Unknown credential format: " + format);
    }
}
