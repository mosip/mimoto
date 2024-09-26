package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.PathMatcher;

@RunWith(MockitoJUnitRunner.class)

public class DataShareServiceTest {

    @Mock
    RestApiClient restApiClient;
    @Mock
    ObjectMapper objectMapper;
    @Mock
    PathMatcher pathMatcher;
    @InjectMocks
    DataShareServiceImpl dataShareService;

    @Before
    public void setUp(){
        ReflectionTestUtils.setField(dataShareService, "dataShareHostUrl", "https://test-url");
        ReflectionTestUtils.setField(dataShareService, "dataShareCreateUrl", "https://test-url");
        ReflectionTestUtils.setField(dataShareService, "dataShareGetUrlPattern", "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*");
        ReflectionTestUtils.setField(dataShareService, "maxRetryCount", 1);
    }

    @Test
    public void storeDataInDataShareWhenProperDataIsPassed() throws Exception {
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = TestUtilities.getDataShareResponseWrapperDTO();
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenReturn(dataShareResponseWrapperDTO);
        String actualDataShareLink = dataShareService.storeDataInDataShare("SampleData");
        String expectedDataShareLink = dataShareResponseWrapperDTO.getDataShare().getUrl();
        Assert.assertEquals(expectedDataShareLink, actualDataShareLink);
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwRequestTimedOutExceptionWhenMaxCountIsReached() throws Exception {
        ReflectionTestUtils.setField(dataShareService, "maxRetryCount", 0);
        dataShareService.storeDataInDataShare("SampleData");
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwServiceUnavailableExceptionWhenCredentialPushIsNotDone() throws Exception {
        ReflectionTestUtils.setField(dataShareService, "maxRetryCount", 1);
        Mockito.when(restApiClient.postApi(Mockito.anyString(), Mockito.eq(MediaType.MULTIPART_FORM_DATA), Mockito.any(), Mockito.eq(DataShareResponseWrapperDTO.class)))
                .thenThrow(InvalidCredentialResourceException.class);
        dataShareService.storeDataInDataShare("SampleData");
    }

    @Test
    public void downloadCredentialWhenRequestIsProper() throws Exception {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        String credentialString = TestUtilities.getObjectAsString(vcCredentialResponseDTO);
        Mockito.when(restApiClient.getApi(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"), Mockito.eq(String.class)))
                .thenReturn(credentialString);
        Mockito.when(objectMapper.readValue(Mockito.eq(credentialString), Mockito.eq(VCCredentialResponse.class)))
                        .thenReturn(vcCredentialResponseDTO);
        Mockito.when(pathMatcher.match(Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/*"),Mockito.eq("http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test"))).thenReturn(true);
        VCCredentialResponse actualVCCredentialResponse = dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);
        Assert.assertEquals(vcCredentialResponseDTO, actualVCCredentialResponse);
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwServiceUnavailableExceptionWhenCredentialIsNotFetched() throws Exception {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);
    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwResourceExpiredExceptionWhenCredentialIsExpired() throws Exception {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        vcCredentialResponseDTO.setCredential(null);
        dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);

    }

    @Test(expected = InvalidCredentialResourceException.class)
    public void throwInvalidResourceExceptionWhenResourceURLDoesnotMatchPattern() throws Exception {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setResource("test-resource");
        VCCredentialResponse vcCredentialResponseDTO = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        vcCredentialResponseDTO.setCredential(null);
        dataShareService.downloadCredentialFromDataShare(presentationRequestDTO);

    }

}
