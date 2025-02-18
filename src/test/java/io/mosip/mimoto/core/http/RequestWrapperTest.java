package io.mosip.mimoto.core.http;

import io.mosip.mimoto.core.http.dto.RequestDTO;
import jakarta.validation.Validator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class RequestWrapperTest {
    @Autowired
    private Validator validator;

    RequestDTO requestDTO1, requestDTO2;
    String id, version, requestTime;
    Object metadata;

    RequestWrapper<RequestDTO> wrapper1, wrapper2;

    @Before
    public void setUp() {
        id = "id1";
        version = "v1";
        requestTime = "time1";
        metadata = "metadata1";
        requestDTO1 = new RequestDTO("data");
        wrapper1 = new RequestWrapper<>();
        wrapper1.setRequest(requestDTO1);
        wrapper1.setId(id);
        wrapper1.setVersion(version);
        wrapper1.setRequesttime(requestTime);
        wrapper1.setMetadata(metadata);
        requestDTO2 = new RequestDTO("data");
        wrapper2 = new RequestWrapper<>();
        wrapper2.setRequest(requestDTO2);
        wrapper2.setId(id);
        wrapper2.setVersion(version);
        wrapper2.setRequesttime(requestTime);
        wrapper2.setMetadata(metadata);
    }

    @Test
    public void testRequestWrapperWithValidData() {
        assertThat(wrapper1)
                .extracting("id", "version", "requesttime", "metadata", "request")
                .containsExactly(id, version, requestTime, metadata, requestDTO1);
    }

    @Test
    public void testRequestWrapperWithNullRequest() {
        wrapper1.setRequesttime(null);

        assertThrows(NullPointerException.class, () -> validator.validate(wrapper1));
    }

    @Test
    public void testRequestWrapperEmptyConstructor() {
        wrapper1 = new RequestWrapper<>();

        assertThat(wrapper1)
                .extracting("id", "version", "requesttime", "metadata", "request")
                .containsExactly(null, null, null, null, null);
    }

    @Test
    public void testHashCodeForEqualObjects() {
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1.hashCode()).isEqualTo(wrapper2.hashCode());
    }

    @Test
    public void testHashCodeForDifferentObjects() {
        assertThat(wrapper1.hashCode()).isNotEqualTo(wrapper2.hashCode());
    }

    @Test
    public void testCanEqual() {
        assertThat(wrapper1.canEqual(wrapper2)).isTrue();
        assertThat(wrapper1.canEqual(new Object())).isFalse();
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithSameTestDTOs() {
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1.equals(wrapper2)).isTrue();
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentTestDTOs() {
        assertThat(wrapper1.equals(wrapper2)).isFalse();
    }

    @Test
    public void testObjectToStringConversionForSuccessScenario() {
        assertThat(wrapper1.toString())
                .isNotNull()
                .contains("id=id1")
                .contains("version=v1")
                .contains("requesttime=time1")
                .contains("metadata=metadata1")
                .contains("request=io.mosip.mimoto.core.http.dto.RequestDTO@");
    }

    @Test
    public void testObjectToStringConversionWhenRequestIsNull() {
        wrapper1.setRequest(null);
        String expectedString = "RequestWrapper(id=id1, version=v1, requesttime=time1, metadata=metadata1, request=null)";

        String actualString = wrapper1.toString();

        assertEquals(expectedString, actualString);
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentRequests() {
        assertThat(wrapper1).isNotEqualTo(wrapper2);
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentIds() {
        wrapper2.setId("id2");
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1).isNotEqualTo(wrapper2);
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentVersions() {
        wrapper2.setVersion("v2");
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1).isNotEqualTo(wrapper2);
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentRequestTimes() {
        wrapper2.setRequesttime("time2");
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1).isNotEqualTo(wrapper2);
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentMetadata() {
        wrapper2.setMetadata("metadata2");
        wrapper2.setRequest(requestDTO1);

        assertThat(wrapper1).isNotEqualTo(wrapper2);
    }
}