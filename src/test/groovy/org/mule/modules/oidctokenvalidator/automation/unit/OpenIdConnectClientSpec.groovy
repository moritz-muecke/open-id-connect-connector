package org.mule.modules.oidctokenvalidator.automation.unit

import org.mule.modules.oidctokenvalidator.client.OpenIdConnectClient
import org.mule.modules.oidctokenvalidator.client.relyingparty.RelyingPartyHandler
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenValidator
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig
import spock.lang.Specification


/**
 * Created by moritz.moeller on 08.03.2016.
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
        1 * handler.handleRequest()
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
        0 * handler.handleRequest()
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
        0 * handler.handleRequest()
        1 * handler.hasRedirectCookieAndIsStored() >> false
        0 * handler.handleTokenRequest()
        1 * handler.handleRedirect()
    }
}