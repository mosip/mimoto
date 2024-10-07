package io.mosip.mimoto.util;

import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * The Class CbeffToBiometricUtil.
 *
 * @author Monobikash Das
 */
@Component
public class CbeffToBiometricUtil {

    /** The cbeffutil. */
    @Autowired
    private CbeffUtil cbeffutil;
    /** the bioApi */

    /**
     * Gets the photo by type and sub type.
     *
     * @param bIRList the b IR type list
     * @param type        the type
     * @param subType     the sub type
     * @return the photo by type and sub type
     */
    public byte[] getPhotoByTypeAndSubType(List<BIR> bIRList, String type, List<String> subType) {
        byte[] photoBytes = null;
        for (BIR bir : bIRList) {
            if (bir.getBdbInfo() != null) {
                List<BiometricType> singleTypeList = bir.getBdbInfo().getType();
                List<String> subTypeList = bir.getBdbInfo().getSubtype();

                boolean isType = isBiometricType(type, singleTypeList);
                boolean isSubType = isSubType(subType, subTypeList);

                if (isType && isSubType) {
                    photoBytes = bir.getBdb();
                    break;
                }
            }
        }
        return photoBytes;
    }

    /**
     * Checks if is sub type.
     *
     * @param subType     the sub type
     * @param subTypeList the sub type list
     * @return true, if is sub type
     */
    private boolean isSubType(List<String> subType, List<String> subTypeList) {
        return subTypeList.equals(subType) ? Boolean.TRUE : Boolean.FALSE;
    }

    private boolean isBiometricType(String type, List<BiometricType> biometricTypeList) {
        boolean isType = false;
        for (BiometricType biometricType : biometricTypeList) {
            if (biometricType.value().equalsIgnoreCase(type)) {
                isType = true;
            }
        }
        return isType;
    }

    /**
     * Gets the BIR type list.
     *
     * @param cbeffFileString the cbeff file string
     * @return the BIR type list
     * @throws Exception the exception
     */

    public List<BIR> getBIRTypeList(String cbeffFileString) throws Exception {
        return cbeffutil.getBIRDataFromXML(Base64.decodeBase64(cbeffFileString));
    }

}
