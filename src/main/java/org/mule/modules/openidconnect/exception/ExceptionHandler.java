/**
 * Copyright 2016 Moritz Möller, AOE GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
