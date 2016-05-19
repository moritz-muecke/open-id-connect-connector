package org.mule.modules.openidconnect.exception;

import org.mule.api.annotations.Handle;
import org.mule.api.annotations.components.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class to handle exceptions thrown by a mule message processor
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
@Handler
public class ExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(ExceptionHandler.class);

    @Handle
    public void handleException(Exception e) throws Exception {
        if (e instanceof TokenValidationException) {
            logger.debug("Token validation failed. Reason: {}", e.getMessage());
        } else if (e instanceof HTTPConnectException) {
            logger.error("Error while sending HTTP request to identity provider. Reason: {}", e.getMessage());
        } else if (e instanceof MetaDataInitializationException) {
            logger.error("Error while initializing identity provider metadata. Reason: {}", e.getMessage());
        } else {
            logger.error("Error during token validation. Reason: {}", e.getMessage());
        }
    }
}
