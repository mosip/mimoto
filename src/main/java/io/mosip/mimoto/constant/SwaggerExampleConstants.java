package io.mosip.mimoto.constant;

public class SwaggerExampleConstants {

    public static final String ALL_PROPERTIES_EXAMPLE = """
                    {
                        "response": {
                            "modelDownloadMaxRetry": "10",
                            "audience": "ida-binding",
                            "datashare.host": "https://datashare-inji.collab.mosip.net",
                            "allowedInternalAuthType": "otp,bio-Finger,bio-Iris,bio-Face",
                            "openId4VCIDownloadVCTimeout": "30000",
                            "qr.code.height": "650",
                            "ovp.error.redirect.url.pattern": "%s?error=%s&error_description=%s",
                            "vcDownloadMaxRetry": "10",
                            "ovp.qrdata.pattern": "INJI_OVP://https://injiweb.collab.mosip.net/authorize?response_type=vp_token&resource=%s&presentation_definition=%s",
                            "minStorageRequiredForAuditEntry": "2",
                            "minStorageRequired": "2",
                            "vcDownloadPoolInterval": "6000",
                            "issuer": "residentapp",
                            "ovp.redirect.url.pattern": "%s#vp_token=%s&presentation_submission=%s",
                            "allowedAuthType": "demo,otp,bio-Finger,bio-Iris,bio-Face",
                            "allowedEkycAuthType": "demo,otp,bio-Finger,bio-Iris,bio-Face",
                            "warningDomainName": "https://api.collab.mosip.net",
                            "qr.code.width": "650",
                            "web.host": "https://injiweb.collab.mosip.net",
                            "web.redirect.url": "https://injiweb.collab.mosip.net/authorize",
                            "aboutInjiUrl": "https://docs.mosip.io/inji/inji-mobile-wallet/overview",
                            "qr.data.size.limit": "10000",
                            "faceSdkModelUrl": "https://api.collab.mosip.net/inji"
                        },
                        "errors": []
                    }
                    """;
}
