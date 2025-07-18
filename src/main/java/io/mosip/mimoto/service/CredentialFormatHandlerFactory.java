package io.mosip.mimoto.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class CredentialFormatHandlerFactory {

    private final Map<String, CredentialFormatHandler> handlers;

    @Autowired
    public CredentialFormatHandlerFactory(List<CredentialFormatHandler> handlers) {
        this.handlers = handlers.stream()
                .collect(Collectors.toMap(
                        CredentialFormatHandler::getSupportedFormat,
                        Function.identity()
                ));
    }

    public CredentialFormatHandler getHandler(String format) {
        CredentialFormatHandler processor = handlers.get(format);
        if (processor == null) {
            throw new IllegalArgumentException("Unsupported credential format: " + format);
        }
        return processor;
    }
}
