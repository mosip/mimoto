package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.util.DateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class CommonInjiController {

    @Autowired
    private Map<String, String> injiConfig;

    @GetMapping("/allProperties")
    public ResponseEntity<Object> getAllProperties() {
        ResponseWrapper<Map<String, String>> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId("mosip.inji.properties");
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());
        responseWrapper.setResponse(injiConfig);
        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }
}
