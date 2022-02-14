package io.mosip.residentapp.service;

import io.mosip.residentapp.model.EventModel;

public interface CredentialShareService {
    
    /**
     * Generate documents from websub event model.
     *
     * @param eventModel
     * @return
     * @throws Exception
     */
    public boolean generateDocuments(EventModel eventModel) throws Exception;
}