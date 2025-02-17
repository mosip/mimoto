package io.mosip.mimoto.core.http;

import io.mosip.mimoto.dto.ErrorDTO;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
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


// Example DTO for testing
class TestDTO {
    private String name;

    public TestDTO(String name) {
        this.name = name;
    }
}

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
@Slf4j
public class ResponseWrapperTest {

    @Autowired
    private Validator validator;
    TestDTO testDTO, testDTO1, testDTO2;

    @Before
    public void setUp() {
        testDTO = new TestDTO("test-name");
        testDTO1 = new TestDTO("test-name");
        testDTO2 = new TestDTO("test-name");
    }

    @Test
    public void testResponseWrapper_withValidResponse() {
        ResponseWrapper<TestDTO> wrapper = new ResponseWrapper<>();
        wrapper.setResponse(testDTO);

        assertThat(wrapper.getResponse()).isEqualTo(testDTO);
        assertThat(wrapper.getErrors()).isEmpty();
    }

    @Test
    public void testResponseWrapper_withNullResponse() {
        ResponseWrapper<TestDTO> wrapper = new ResponseWrapper<>();
        wrapper.setResponse(null);

        assertThrows(NullPointerException.class, () -> validator.validate(wrapper));
    }


    @Test
    public void testResponseWrapper_withErrors() {
        ResponseWrapper<TestDTO> wrapper = new ResponseWrapper<>();
        ErrorDTO error1 = new ErrorDTO("error code 1", "error message 1");
        ErrorDTO error2 = new ErrorDTO("error code 2", "error message 2");
        wrapper.setErrors(List.of(error1, error2));

        assertThat(wrapper.getResponse()).isNull();
        assertThat(wrapper.getErrors()).hasSize(2);
        assertThat(wrapper.getErrors()).containsExactly(error1, error2);
    }

    @Test
    public void testResponseWrapper_emptyConstructor() {
        ResponseWrapper<TestDTO> wrapper = new ResponseWrapper<>();

        assertThat(wrapper.getErrors()).isEmpty();
        assertThat(wrapper.getResponse()).isNull();
    }

    @Test
    public void testHashCodeForEqualObjects() {
        ResponseWrapper<TestDTO> wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(testDTO);

        ResponseWrapper<TestDTO> wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(testDTO);

        assertThat(wrapper1.hashCode()).isEqualTo(wrapper2.hashCode());
    }

    @Test
    public void testHashCodeForDifferentObjects() {
        ResponseWrapper<TestDTO> wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(testDTO1);

        ResponseWrapper<TestDTO> wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(testDTO2);

        assertThat(wrapper1.hashCode()).isNotEqualTo(wrapper2.hashCode());
    }

    @Test
    public void testCanEqual() {
        ResponseWrapper<TestDTO> wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(testDTO1);

        ResponseWrapper<TestDTO> wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(testDTO2);

        assertThat(wrapper1.canEqual(wrapper2)).isTrue();
        assertThat(wrapper1.canEqual(new Object())).isFalse();
    }

    @Test
    public void testEqualsForTwoObjectsWithDifferentContent() {
        ResponseWrapper<TestDTO> wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(testDTO);

        ResponseWrapper<TestDTO> wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(testDTO);

        assertThat(wrapper1.equals(wrapper2)).isTrue();
    }

    @Test
    public void testEqualsForTwoObjectsWithSameContent() {
        ResponseWrapper<TestDTO> wrapper1 = new ResponseWrapper<>();
        wrapper1.setResponse(testDTO1);

        ResponseWrapper<TestDTO> wrapper2 = new ResponseWrapper<>();
        wrapper2.setResponse(testDTO2);

        assertThat(wrapper1.equals(wrapper2)).isFalse();
    }

    @Test
    public void testObjectToStringConversionForSuccessScenario() {
        ResponseWrapper<String> person = new ResponseWrapper<>();
        person.setResponse("Hello world");
        String expectedString = "ResponseWrapper(response=Hello world, errors=[])";

        String actualString = person.toString();

        assertEquals(expectedString, actualString);
    }

    @Test
    public void testObjectToStringConversionForErrorScenario() {
        ResponseWrapper<String> person = new ResponseWrapper<>();
        person.setErrors(List.of(new ErrorDTO("code", "message")));
        String expectedString = "ResponseWrapper(response=null, errors=[ErrorDTO(errorCode=code, errorMessage=message)])";

        String actualString = person.toString();

        assertEquals(expectedString, actualString);
    }
}