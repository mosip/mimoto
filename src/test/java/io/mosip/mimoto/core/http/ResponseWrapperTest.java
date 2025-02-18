package io.mosip.mimoto.core.http;

import io.mosip.mimoto.core.http.dto.ResponseDTO;
import io.mosip.mimoto.dto.ErrorDTO;
import jakarta.validation.Validator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class ResponseWrapperTest {

    @Autowired
    private Validator validator;
    ResponseDTO responseDTO1, responseDTO2;
    ResponseWrapper<ResponseDTO> wrapper1, wrapper2;

    @Before
    public void setUp() {
        responseDTO1 = new ResponseDTO("test-name");
        responseDTO2 = new ResponseDTO("test-name");
        wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(responseDTO1);
        wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(responseDTO2);
    }

    @Test
    public void testResponseWrapperWithValidResponse() {
        assertThat(wrapper1.getResponse()).isEqualTo(responseDTO1);
        assertThat(wrapper1.getErrors()).isEmpty();
    }

    @Test
    public void testResponseWrapperWithNullResponse() {
        wrapper1.setResponse(null);

        assertThrows(NullPointerException.class, () -> validator.validate(wrapper1));
    }


    @Test
    public void testResponseWrapperWithErrors() {
        wrapper1.setResponse(null);
        ErrorDTO error1 = new ErrorDTO("error code 1", "error message 1");
        ErrorDTO error2 = new ErrorDTO("error code 2", "error message 2");

        wrapper1.setErrors(List.of(error1, error2));

        assertThat(wrapper1.getResponse()).isNull();
        assertThat(wrapper1.getErrors()).hasSize(2);
        assertThat(wrapper1.getErrors()).containsExactly(error1, error2);
    }

    @Test
    public void testResponseWrapperEmptyConstructor() {
        wrapper1 = new ResponseWrapper<>();

        assertThat(wrapper1.getErrors()).isEmpty();
        assertThat(wrapper1.getResponse()).isNull();
    }

    @Test
    public void testHashCodeForEqualObjects() {
        wrapper2.setResponse(responseDTO1);

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
    public void testEqualsForTwoWrapperObjectsWithSameRequestDTOs() {
        wrapper2.setResponse(responseDTO1);

        assertThat(wrapper1.equals(wrapper2)).isTrue();
    }

    @Test
    public void testEqualsForTwoWrapperObjectsWithDifferentRequestDTOsOfSameContent() {
        assertThat(wrapper1.equals(wrapper2)).isFalse();
    }

    @Test
    public void testEqualsWithNull() {
        assertThat(wrapper1.equals(null)).isFalse();
    }

    @Test
    public void testEqualsForWrapperClassAndStringClass() {
        assertThat(wrapper1.equals("Hello World!!")).isFalse();
    }

    @Test
    public void testEqualsWithSameInstance() {
        assertThat(wrapper1.equals(wrapper1)).isTrue();
    }

    @Test
    public void testObjectToStringConversionForSuccessScenario() {
        assertThat(wrapper1.toString())
                .isNotNull()
                .contains("response")
                .contains("errors");
    }

    @Test
    public void testObjectToStringConversionForErrorScenario() {
        wrapper1.setResponse(null);
        wrapper1.setErrors(List.of(new ErrorDTO("code", "message")));
        String expectedString = "ResponseWrapper(response=null, errors=[ErrorDTO(errorCode=code, errorMessage=message)])";

        String actualString = wrapper1.toString();

        assertEquals(expectedString, actualString);
    }
}