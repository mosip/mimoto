package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;

public interface AuthorizationServerService {
    AuthorizationServerWellKnownResponse getWellknown(String authorizationServerHostUrl) throws AuthorizationServerWellknownResponseException;
}
