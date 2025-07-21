package io.mosip.mimoto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class SigningAlgorithmConfig {

    @Value("${signing.algorithms.priority.order}")
    private String signingAlgorithmsPriorityOrder;

    public List<String> getSigningAlgorithmsPriorityOrder() {
        return Arrays.asList(signingAlgorithmsPriorityOrder.split(","));
    }
}
