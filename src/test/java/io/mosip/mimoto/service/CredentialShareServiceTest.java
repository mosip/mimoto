package io.mosip.mimoto.service;

import com.google.common.collect.Lists;
import io.mosip.biometrics.util.CommonUtil;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.AuditResponseDto;
import io.mosip.mimoto.dto.CryptoWithPinResponseDto;
import io.mosip.mimoto.exception.DocumentGeneratorException;
import io.mosip.mimoto.model.Event;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import io.mosip.mimoto.util.*;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URI;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ URI.class, org.json.JSONObject.class, CommonUtil.class})
@PowerMockIgnore({ "javax.management.*", "javax.net.ssl.*","com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "javax.management.*" })
public class CredentialShareServiceTest {

    @InjectMocks
    private CredentialShareService service = new CredentialShareServiceImpl();

    @Mock
    public RestApiClient restApiClient;

    @Mock
    public AuditLogRequestBuilder auditLogRequestBuilder;

    @Mock
    private CryptoCoreUtil cryptoCoreUtil;

    @Mock
    CryptoUtil cryptoUtil;

    @Mock
    private Utilities utilities;

    private EventModel eventModel = null;

    @Mock
    private CbeffToBiometricUtil util;

    @Before
    public void setup() throws Exception {
        Map<String, String> proofMap = new HashMap<>();
        proofMap.put("signature", "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJQUzI1NiJ9..XSGdtAvEdcSrdHiyC8pP8orML1v3akfHru821aMVNKSa9ftx3DIS1ZbqNL-DNxWmdLjcINpsWIbwyD7Lbn0MZNIsmR5SjJJa31cB710aFpMfQgHY0R2cgh8XJWIU4Whs8Tvt9RWJ2la0CkIdeukEjxKQs2Ier1x3wzbVSK6OeoYO6tM77saDsDciu88JGRLt5zdkNyc9hN0XNwH3SPG1hJOKV4QUHW3CzIFGKvcR-VZHD7iAyqrgVNjEt1IU7ghdqH38xiTZ-2QfJDkH90yUmUEkHJ-AcXlFZATIi3YYPY9UNSBEZeHaN-fOwrPETftTo6a_DZiYIYeW1eYVs_hvnA\",\n" +
                "        \"proofPurpose\": \"assertionMethod");
        Map<String, Object> data = new HashMap<>();
        data.put("credential", "credential");
        data.put("protectionKey", "12345");
        data.put("credentialType", "VERCRED");
        data.put("proof", proofMap);
        Event event = new Event();
        event.setDataShareUri("https://www.datashare.com");
        event.setData(data);
        event.setTransactionId("transactionid");
        eventModel = new EventModel();
        eventModel.setEvent(event);

        CryptoWithPinResponseDto cryptoWithPinResponseDto = new CryptoWithPinResponseDto();
        cryptoWithPinResponseDto.setData("biometrics");

        Mockito.when(cryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenReturn(cryptoWithPinResponseDto);
        Mockito.when(utilities.getDataPath()).thenReturn("target");
        Mockito.when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn("credential");
        Mockito.when(cryptoCoreUtil.decrypt(Mockito.anyString())).thenReturn("{\"credentialSubject\":{\"biometrics\":\"biometrics\"},\"protectedAttributes\":[\"biometrics\"]}");
        Map<String, String> templateMap = new HashMap<>();
        templateMap.put("biometrics", "biometrics");
        JSONObject templateJSON = new JSONObject(templateMap);

        Mockito.when(utilities.getTemplate()).thenReturn(templateJSON);

        Mockito.when(auditLogRequestBuilder.createAuditRequestBuilder(
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.any())).thenReturn(new ResponseWrapper<AuditResponseDto>());


        BIR bir = new BIR();
        BDBInfo bdbInfo = new BDBInfo();
        bdbInfo.setType(Lists.newArrayList(BiometricType.FACE));
        bir.setBdbInfo(bdbInfo);
        List<BIR> birs = Lists.newArrayList(bir);
        Mockito.when(util.getBIRTypeList(Mockito.anyString())).thenReturn(birs);
        Mockito.when(util.getPhotoByTypeAndSubType(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("face image strring".getBytes());

        /*PowerMockito.mockStatic(CommonUtil.class);
        Mockito.when(CommonUtil.convertJP2ToJPEGBytes(Mockito.any(byte[].class))).thenReturn(("VkVSX1IyUePARBpE1-kwFG3i9AXxWsH67-sAbyvWC1joGfw-QgFjLTgLRCwUrzaPC0_K1NuXl" +
                "t_TNHNyGu0aAcyqMe3zbBBgZXiP0sImJ0OjjkdbpjBdO_BGyWpLsz-T5eW3luz2RILFSKpDtTwDAVJ8y2jsSONgWDUza14cglCHvt9MT6UWv18oYJ8uCw2Aqx3Pf3Op" +
                "9P3HJd_32G03U6HhrHD9AVRCon9R2Uh2IYgUmn8zwKozC7bWoGqO74LCYt15zsmYTvJg9v9zqVUAPxrPvo5VVJmbKm_kP8ZPtkslnPte_EML4wkVvZDPpa7D6H3aIn-t" +
                "2l8G7w8zWRwnTjrQqBn_fmTS43cabLyr3Vc2RmVd0LOX_LXuikS-n5gEjy-Xw6Yc-xAZb0F_spB2Q_ihAi9Ej2FMAXa1Why1MYp0jNCK1FIyTns5S9oc7bonaaK5Zo1aqkut" +
                "v_I2wWvYKOR2UxXLmfPzgcjFDVpnIG3hDSGn-1Oat2liFgKBM_cBQvapPyMgqE3CokFI6DAvBeHJrOgtR1k5m4JuRsqwtrzf3_PCBFHW6jkEjYm9VJc5zBgAFi-0KiZoRF" +
                "a-XG4L3ZCA42gOfTAlQ6iVq0_3M5uxi4BdSkr1Cyr0CBHZgAivU5vyajLbnvvJVlbDpGb_T3LqG7l7oBVvo9zq74QbQFKOaKwzJn9432_yD4DG2qOHBPnOmyopfxaSSoosM" +
                "1qmDxC9CaE2zVWDjmJdPk630AkKJhvNmMJJXxkeZnvsGg5QsjP4_i2isLg63kjhb2MtNtgN0uCUsXNbqEyb3kJAVvM34KGR1bsmO5Zowq_yKenNCFm68zNWm05pFMW0_4").getBytes());
    */
    }

    @Test
    public void generateDocumentsTest() throws Exception {

        boolean result = service.generateDocuments(eventModel);

        assertTrue(result);
    }

    @Test
    public void documentExceptionTest() throws Exception {

        Mockito.when(cryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenThrow(new InvalidKeyException("exception"));

        boolean result = service.generateDocuments(eventModel);

        assertFalse(result);

    }

    /*@Test(expected = DocumentGeneratorException.class)
    public void documentFailedExceptionTest() throws Exception {

        Mockito.when(cryptoUtil.decryptWithPin(ArgumentMatchers.any())).thenThrow(new Exception("exception"));

        boolean result = service.generateDocuments(eventModel);

       // assertFalse(result);

    }*/

}
