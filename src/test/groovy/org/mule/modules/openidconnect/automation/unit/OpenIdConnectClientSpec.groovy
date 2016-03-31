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
        1 * handler.hasTokenCookieAndIsStored() >> true
        1 * handler.handleResourceRequest()
        0 * handler.hasRedirectCookieAndIsStored()
        0 * handler.handleTokenRequest()
        0 * handler.handleRedirect()
    }

    def "act as relying party with existing and stored request cookie"() {
        given:
        def handler = Mock(RelyingPartyHandler)

        when:
        client.actAsRelyingParty(handler)

        then:
        1 * handler.hasTokenCookieAndIsStored() >> false
        0 * handler.handleResourceRequest()
        1 * handler.hasRedirectCookieAndIsStored() >> true
        1 * handler.handleTokenRequest()
        0 * handler.handleRedirect()
    }

    def "act as relying party without cookies"() {
        given:
        def handler = Mock(RelyingPartyHandler)

        when:
        client.actAsRelyingParty(handler)

        then:
        1 * handler.hasTokenCookieAndIsStored() >> false
        0 * handler.handleResourceRequest()
        1 * handler.hasRedirectCookieAndIsStored() >> false
        0 * handler.handleTokenRequest()
        1 * handler.handleRedirect()
    }
}