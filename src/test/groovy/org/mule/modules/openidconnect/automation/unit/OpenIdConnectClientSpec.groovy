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
package org.mule.modules.openidconnect.automation.unit

import org.mule.modules.openidconnect.client.OpenIdConnectClient
import org.mule.modules.openidconnect.client.relyingparty.RelyingPartyHandler
import org.mule.modules.openidconnect.client.tokenvalidation.TokenValidator
import org.mule.modules.openidconnect.config.SingleSignOnConfig
import spock.lang.Specification


/**
 * Test specification for the OpenIdConnectClient
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class OpenIdConnectClientSpec extends Specification {
    def tokenValidator = Mock(TokenValidator)
    def ssoConfig = Mock(SingleSignOnConfig)
    def client = new OpenIdConnectClient(ssoConfig, tokenValidator)

    def "act as relying party with existing and stored token cookie"() {
        given:
        def handler = Mock(RelyingPartyHandler)

        when:
        client.actAsRelyingParty(handler)

        then:
        1 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME) >> true
        1 * handler.handleResourceRequest()
        0 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME)
        0 * handler.handleTokenRequest()
        0 * handler.handleRedirect()
    }

    def "act as relying party with existing and stored request cookie"() {
        given:
        def handler = Mock(RelyingPartyHandler)

        when:
        client.actAsRelyingParty(handler)

        then:
        1 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME) >> false
        0 * handler.handleResourceRequest()
        1 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME) >> true
        1 * handler.handleTokenRequest()
        0 * handler.handleRedirect()
    }

    def "act as relying party without cookies"() {
        given:
        def handler = Mock(RelyingPartyHandler)

        when:
        client.actAsRelyingParty(handler)

        then:
        1 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME) >> false
        0 * handler.handleResourceRequest()
        1 * handler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME) >> false
        0 * handler.handleTokenRequest()
        1 * handler.handleRedirect()
    }
}