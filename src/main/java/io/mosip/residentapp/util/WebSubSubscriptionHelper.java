package io.mosip.residentapp.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.kernel.core.websub.spi.SubscriptionClient;
import io.mosip.kernel.websub.api.exception.WebSubClientException;
import io.mosip.kernel.websub.api.model.SubscriptionChangeRequest;
import io.mosip.kernel.websub.api.model.SubscriptionChangeResponse;
import io.mosip.kernel.websub.api.model.UnsubscriptionRequest;

@Component
public class WebSubSubscriptionHelper {

    @Value("${mosip.event.hub.subUrl}")
    private String webSubHubSubUrl;

    @Value("${mosip.event.hub.pubUrl}")
    private String webSubHubPubUrl;

    @Value("${mosip.event.secret}")
    private String webSubSecret;

    @Value("${mosip.event.callBackUrl}")
    private String callBackUrl;

    @Value("${mosip.event.topic}")
    private String topic;

    @Autowired
    SubscriptionClient<SubscriptionChangeRequest, UnsubscriptionRequest, SubscriptionChangeResponse> sb;

    @Autowired
    private PublisherClient<String, Object, HttpHeaders> pb;

    private Logger logger = LoggerUtil.getLogger(WebSubSubscriptionHelper.class);

    @Scheduled(
        fixedDelayString    = "${websub-resubscription-delay-millisecs}",
        initialDelayString  = "${mosip.event.delay-millisecs}"
    )
    public void initSubscriptions() {
        logger.info("Initializing subscriptions...");
        subscribeEvent(topic, callBackUrl, webSubSecret);
    }

    public SubscriptionChangeResponse unSubscribeEvent(String topic, String callBackUrl) {
        try {
            UnsubscriptionRequest unsubscriptionRequest = new UnsubscriptionRequest();
            unsubscriptionRequest.setCallbackURL(callBackUrl);
            unsubscriptionRequest.setHubURL(webSubHubSubUrl);
            unsubscriptionRequest.setTopic(topic);
            logger.info("Unsubscription request : {}", unsubscriptionRequest);
            return sb.unSubscribe(unsubscriptionRequest);
        } catch (WebSubClientException e) {
            logger.info("Websub unsubscription error: {} ", e.getMessage());
        }
        return null;
    }

    public SubscriptionChangeResponse subscribeEvent(String topic, String callBackUrl, String secret) {
        try {
            SubscriptionChangeRequest subscriptionRequest = new SubscriptionChangeRequest();
            subscriptionRequest.setCallbackURL(callBackUrl);
            subscriptionRequest.setHubURL(webSubHubSubUrl);
            subscriptionRequest.setSecret(secret);
            subscriptionRequest.setTopic(topic);
            logger.info("Subscription request : {}", subscriptionRequest);
            return sb.subscribe(subscriptionRequest);
        } catch (WebSubClientException e) {
            logger.info("Websub subscription error: {}", e.getMessage());
        }
        return null;
    }

    public void publish(String topic, Object payload) {
        try {
            HttpHeaders headers = new HttpHeaders();
            pb.publishUpdate(topic, payload, MediaType.APPLICATION_JSON_UTF8_VALUE, headers, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            logger.info("Websub publish update error: {}", e.getMessage());
        }

    }

    @Cacheable(value = "topics", key = "{#topic}")
    public void registerTopic(String topic) {
        try {
            pb.registerTopic(topic, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            logger.info("Topic already registered: {}", e.getMessage());
        }

    }

    @Cacheable(value = "topics", key = "{#topic}")
    public void unRegisterTopic(String topic) {
        try {
            pb.unregisterTopic(topic, webSubHubPubUrl);
        } catch (WebSubClientException e) {
            logger.info("Topic already unregistered: {}", e.getMessage());
        }

    }
}
