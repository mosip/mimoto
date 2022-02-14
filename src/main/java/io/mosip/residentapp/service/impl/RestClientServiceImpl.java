package io.mosip.residentapp.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.residentapp.constant.ApiName;
import io.mosip.residentapp.exception.ApisResourceAccessException;
import io.mosip.residentapp.exception.PlatformErrorMessages;
import io.mosip.residentapp.service.RestClientService;
import io.mosip.residentapp.util.LoggerUtil;
import io.mosip.residentapp.util.RestApiClient;

/**
 * The Class RestClientServiceImpl.
 * 
 * @author Rishabh Keshari
 */
@Service
public class RestClientServiceImpl implements RestClientService<Object> {

    /** The logger. */
    Logger logger = LoggerUtil.getLogger(RestClientServiceImpl.class);

    /** The rest api client. */
    @Autowired
    private RestApiClient restApiClient;

    /** The env. */
    @Autowired
    private Environment env;

    /*
     * (non-Javadoc)
     * 
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#getApi(io.mosip.registration.
     * processor .core.code.ApiName,
     * io.mosip.registration.processor.core.code.RestUriConstant, java.lang.String,
     * java.lang.String, java.lang.Class)
     */
    @Override
    public Object getApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
            Class<?> responseType) throws ApisResourceAccessException {
        logger.debug("RestClientServiceImpl::getApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());

        UriComponentsBuilder builder = null;
        UriComponents uriComponents = null;
        if (apiHostIpPort != null) {

            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
            if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
                for (String segment : pathsegments) {
                    if (!((segment == null) || (("").equals(segment)))) {
                        builder.pathSegment(segment);
                    }
                }

            }

            if (!((queryParamName == null) || (("").equals(queryParamName)))) {

                String[] queryParamNameArr = queryParamName.split(",");
                String[] queryParamValueArr = queryParamValue.split(",");
                for (int i = 0; i < queryParamNameArr.length; i++) {
                    builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
                }

            }

            try {

                uriComponents = builder.build(false).encode();
                logger.debug(uriComponents.toUri().toString(), "URI");
                obj = restApiClient.getApi(uriComponents.toUri(), responseType);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION.getCode(), e);

            }
        }
        logger.debug("RestClientServiceImpl::getApi()::exit");
        return obj;
    }

    @Override
    public Object getApi(ApiName apiName, List<String> pathsegments, List<String> queryParamName,
            List<Object> queryParamValue,
            Class<?> responseType) throws ApisResourceAccessException {
        logger.debug("RestClientServiceImpl::getApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());

        UriComponentsBuilder builder = null;
        UriComponents uriComponents = null;
        if (apiHostIpPort != null) {

            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
            if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
                for (String segment : pathsegments) {
                    if (!((segment == null) || (("").equals(segment)))) {
                        builder.pathSegment(segment);
                    }
                }

            }

            if (((queryParamName != null) && (!queryParamName.isEmpty()))) {
                for (int i = 0; i < queryParamName.size(); i++) {
                    builder.queryParam(queryParamName.get(i), queryParamValue.get(i));
                }

            }

            try {

                uriComponents = builder.build(false).encode();
                logger.debug(uriComponents.toUri().toString(), "URI");
                obj = restApiClient.getApi(uriComponents.toUri(), responseType);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION.getCode(), e);

            }
        }
        logger.debug("RestClientServiceImpl::getApi()::exit");
        return obj;
    }

    public Object postApi(ApiName apiName, String queryParamName, String queryParamValue, Object requestedData,
            Class<?> responseType, MediaType mediaType) throws ApisResourceAccessException {
        logger.debug("RestClientServiceImpl::postApi()::entry");

        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!((queryParamName == null) || (("").equals(queryParamName)))) {
                String[] queryParamNameArr = queryParamName.split(",");
                String[] queryParamValueArr = queryParamValue.split(",");

                for (int i = 0; i < queryParamNameArr.length; i++) {
                    builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
                }
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), mediaType, requestedData, responseType);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        logger.debug("RestClientServiceImpl::postApi()::exit");
        return obj;
    }

    /*
     * (non-Javadoc)
     * 
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#postApi(io.mosip.registration.
     * processor.core.code.ApiName,
     * io.mosip.registration.processor.core.code.RestUriConstant, java.lang.String,
     * java.lang.String, java.lang.Object, java.lang.Class)
     */
    @Override
    public Object postApi(ApiName apiName, String queryParamName, String queryParamValue, Object requestedData,
            Class<?> responseType) throws ApisResourceAccessException {
        return postApi(apiName, queryParamName, queryParamValue, requestedData, responseType, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see io.mosip.registration.processor.core.spi.restclient.
     * RestClientService#postApi(io.mosip.registration.
     * processor.core.code.ApiName, java.util.List, java.lang.String,
     * java.lang.String, java.lang.Object, java.lang.Class)
     */
    @Override
    public Object postApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
            Object requestedData, Class<?> responseType) throws ApisResourceAccessException {

        logger.debug("RestClientServiceImpl::postApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
                for (String segment : pathsegments) {
                    if (!((segment == null) || (("").equals(segment)))) {
                        builder.pathSegment(segment);
                    }
                }

            }
            if (!checkNull(queryParamName)) {
                String[] queryParamNameArr = queryParamName.split(",");
                String[] queryParamValueArr = queryParamValue.split(",");

                for (int i = 0; i < queryParamNameArr.length; i++) {
                    builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
                }
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), null, requestedData, responseType);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        logger.debug("RestClientServiceImpl::postApi()::exit");
        return obj;
    }

    @Override
    public Object postApi(ApiName apiName, MediaType mediaType, List<String> pathsegments, List<String> queryParamName,
            List<Object> queryParamValue,
            Object requestedData, Class<?> responseType) throws ApisResourceAccessException {

        logger.debug("RestClientServiceImpl::postApi()::entry");
        Object obj = null;
        String apiHostIpPort = env.getProperty(apiName.name());
        UriComponentsBuilder builder = null;
        if (apiHostIpPort != null)
            builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
        if (builder != null) {

            if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
                for (String segment : pathsegments) {
                    if (!((segment == null) || (("").equals(segment)))) {
                        builder.pathSegment(segment);
                    }
                }

            }
            if (!CollectionUtils.isEmpty(queryParamName)) {

                for (int i = 0; i < queryParamName.size(); i++) {
                    builder.queryParam(queryParamName.get(i), queryParamValue.get(i));
                }
            }

            try {
                obj = restApiClient.postApi(builder.toUriString(), mediaType, requestedData, responseType);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                throw new ApisResourceAccessException(
                        PlatformErrorMessages.RESIDENT_APP_RCT_UNKNOWN_RESOURCE_EXCEPTION.getMessage(), e);

            }
        }
        logger.debug("RestClientServiceImpl::postApi()::exit");
        return obj;
    }

    /**
     * Check null.
     *
     * @param queryParamName
     *                       the query param name
     * @return true, if successful
     */
    private boolean checkNull(String queryParamName) {

        return ((queryParamName == null) || (("").equals(queryParamName)));
    }

}