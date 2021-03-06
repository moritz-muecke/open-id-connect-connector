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

import com.nimbusds.jwt.JWT
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
import com.nimbusds.openid.connect.sdk.Nonce
import org.mule.api.MuleMessage
import org.mule.modules.openidconnect.client.relyingparty.RelyingPartyHandler
import org.mule.modules.openidconnect.client.relyingparty.TokenRequester
import org.mule.modules.openidconnect.client.relyingparty.storage.RedirectData
import org.mule.modules.openidconnect.client.relyingparty.storage.Storage
import org.mule.modules.openidconnect.client.relyingparty.storage.TokenData
import org.mule.modules.openidconnect.client.tokenvalidation.TokenVerifier
import org.mule.modules.openidconnect.config.SingleSignOnConfig
import org.mule.modules.openidconnect.exception.RequestTokenFromSsoException
import spock.lang.Specification


/**
 * Test specification for the RelyingParty
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class RelyingPartyHandlerSpec extends Specification {
    def tokenRequester = Mock(TokenRequester)
    def tokenStorage = Mock(Storage)
    def redirectDataStorage = Mock(Storage)
    def muleMessage = Mock(MuleMessage)
    def tokenVerifier = Mock(TokenVerifier)
    def ssoConfig = Mock(SingleSignOnConfig)

    String cookieHeader = "$RelyingPartyHandler.TOKEN_COOKIE_NAME=tokenCookie; $RelyingPartyHandler.REDIRECT_COOKIE_NAME=redirectCookie"

    def relyingPartyHandler = Spy(RelyingPartyHandler, constructorArgs: [
            muleMessage,
            tokenRequester,
            tokenStorage,
            redirectDataStorage,
            ssoConfig,
            tokenVerifier,
            true
    ])

    def props = new Properties()

    def setup(){
        muleMessage.getInboundProperty('cookie') >> cookieHeader
        props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())))
    }

    def "token cookie from mule message exists in storage"() {
        setup:
        tokenStorage.containsData(_) >> true

        expect:
        relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME)
    }

    def "token cookie from mule message does not exist in storage"() {
        setup:
        tokenStorage.containsData(_) >> false

        expect:
        !relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.TOKEN_COOKIE_NAME)
    }

    def "redirect cookie from mule message exists in storage"() {
        setup:
        redirectDataStorage.containsData(_) >> true

        expect:
        relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME)
    }

    def "redirect cookie from mule message does not exist in storage"() {
        setup:
        redirectDataStorage.containsData(_) >> false

        expect:
        !relyingPartyHandler.hasCookieAndExistsInStore(RelyingPartyHandler.REDIRECT_COOKIE_NAME)
    }

    def "handle request with instant refresh"() {
        given:
        def tokenStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME)
        def tokenData = Mock(TokenData)
        def accessToken = Mock(AccessToken)
        accessToken.value >> "tokenString"
        tokenData.accessToken >> accessToken

        when:
        relyingPartyHandler.setInstantRefresh(true)
        relyingPartyHandler.handleResourceRequest()

        then:
        1 * tokenStorage.getData(tokenStorageId) >> tokenData
        1 * relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> "tokenCookie"
        1 * relyingPartyHandler.refreshTokens(tokenData) >> tokenData
        1 * relyingPartyHandler.storeAndSetCookie(tokenData, tokenStorage, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> null
        1 * muleMessage.setOutboundProperty("Authorization", "Bearer tokenString")
    }

    def "handle request without instant refresh with inactive access token"() {
        given:
        def tokenStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME)
        def tokenData = Mock(TokenData)
        def accessToken = AccessToken.parse(props.getProperty("bearer-auth-header"))
        tokenData.accessToken >> accessToken

        when:
        relyingPartyHandler.setInstantRefresh(false)
        relyingPartyHandler.handleResourceRequest()

        then:
        1 * tokenStorage.getData(tokenStorageId) >> tokenData
        1 * relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> "tokenCookie"
        1 * relyingPartyHandler.refreshTokens(tokenData) >> tokenData
        1 * relyingPartyHandler.storeAndSetCookie(tokenData, tokenStorage, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> null
        1 * muleMessage.setOutboundProperty("Authorization", "Bearer $accessToken.value")
    }

    def "handle request without instant refresh with active access token"() {
        given:
        def tokenStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME)
        def tokenData = Mock(TokenData)
        def accessToken = AccessToken.parse(props.getProperty("bearer-auth-header"))
        tokenData.accessToken >> accessToken

        when:
        relyingPartyHandler.setInstantRefresh(false)
        relyingPartyHandler.handleResourceRequest()

        then:
        1 * tokenStorage.getData(tokenStorageId) >> tokenData
        1 * relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> "tokenCookie"
        1 * tokenVerifier.isActive(accessToken) >> true
        1 * muleMessage.setOutboundProperty("Authorization", "Bearer $accessToken.value")
    }


    def "handle token request with valid state and auth code"() {
        given:
        def redirectStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.REDIRECT_COOKIE_NAME)
        def queryStringMap = [state: 'queryState', code: 'queryCode']
        def redirectData = Mock(RedirectData)
        def nonce = new Nonce('nonce')
        def state = new State('queryState')
        def idtoken = Mock(JWT)
        def tokenData = Mock(TokenData)
        def accessToken = Mock(AccessToken)
        accessToken.value >> "tokenString"
        tokenData.accessToken >> accessToken
        tokenData.idToken >> idtoken
        redirectData.nonce >> nonce

        when:
        relyingPartyHandler.handleTokenRequest()

        then:
        1 * relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.REDIRECT_COOKIE_NAME) >> "redirectCookie"
        1 * redirectDataStorage.getData(redirectStorageId) >> redirectData
        1 * muleMessage.getInboundProperty("http.query.params") >> queryStringMap
        1 * redirectData.state >> state
        1 * tokenRequester.requestTokensFromSso('queryCode', ssoConfig) >> tokenData
        1 * tokenVerifier.verifyIdToken(idtoken, ssoConfig, nonce)
        1 * relyingPartyHandler.storeAndSetCookie(tokenData, tokenStorage, RelyingPartyHandler.TOKEN_COOKIE_NAME) >> null
    }

    def "handle token request with invalid state and auth code"() {
        given:
        def redirectStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.REDIRECT_COOKIE_NAME)
        def queryStringMap = [state: 'queryState', code: null]
        def redirectData = Mock(RedirectData)
        def state = new State('queryState1')

        when:
        relyingPartyHandler.handleTokenRequest()

        then:
        1 * redirectDataStorage.getData(redirectStorageId) >> redirectData
        1 * muleMessage.getInboundProperty("http.query.params") >> queryStringMap
        1 * redirectData.state >> state
        1 * relyingPartyHandler.handleRedirect() >> null
    }

    def "handle token request fails with RequestTokenFromSsoException"() {
        given:
        def redirectStorageId = relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.REDIRECT_COOKIE_NAME)
        def queryStringMap = [state: 'queryState', code: 'queryCode']
        def redirectData = Mock(RedirectData)
        def state = new State('queryState')

        when:
        relyingPartyHandler.handleTokenRequest()

        then:
        1 * relyingPartyHandler.cookieExtractor(cookieHeader, RelyingPartyHandler.REDIRECT_COOKIE_NAME) >> "redirectCookie"
        1 * redirectDataStorage.getData(redirectStorageId) >> redirectData
        1 * muleMessage.getInboundProperty("http.query.params") >> queryStringMap
        1 * redirectData.state >> state
        1 * tokenRequester.requestTokensFromSso('queryCode', ssoConfig) >> {
            throw new RequestTokenFromSsoException("Token request failed")
        }
        0 * tokenVerifier.verifyIdToken(_, _, _)
        0 * relyingPartyHandler.storeAndSetTokenCookie(_)
        1 * relyingPartyHandler.handleRedirect() >> null
    }

    def "handle redirect to sso"() {
        given:
        def authRequest = Mock(AuthenticationRequest)
        def uri = new URI("http://localhost")

        when:
        relyingPartyHandler.handleRedirect()

        then:
        1 * tokenRequester.buildAuthenticationRequest(ssoConfig) >> authRequest
        1 * authRequest.nonce >> new Nonce("nonce")
        1 * authRequest.state >> new State("state")
        1 * relyingPartyHandler.storeAndSetCookie(_, redirectDataStorage, RelyingPartyHandler.REDIRECT_COOKIE_NAME) >> null
        1 * authRequest.toURI() >> uri
        1 * relyingPartyHandler.redirectToUri(uri) >> null
    }

    def "refresh tokens returns token data"() {
        setup:
        def tokenData = Mock(TokenData)
        def refreshedTokenData = Mock(TokenData)
        def idToken = Mock(JWT)
        refreshedTokenData.idToken >> idToken
        tokenData.idToken >> idToken
        tokenRequester.refreshTokenSet(tokenData, ssoConfig) >> refreshedTokenData

        expect:
        relyingPartyHandler.refreshTokens(tokenData) == refreshedTokenData
        relyingPartyHandler.refreshTokens(tokenData).idToken == idToken
    }


    def "refresh tokens fails with RequestTokenFromSsoException and returns null"() {
        given:
        def tokenData = Mock(TokenData)
        tokenRequester.refreshTokenSet(tokenData, ssoConfig) >> {
            throw new RequestTokenFromSsoException("Token request failed")
        }

        when:
        relyingPartyHandler.refreshTokens(tokenData)

        then:
        RequestTokenFromSsoException e = thrown()
        e.message == "Token request failed"
    }

    def "save redirect data in storage and set cookie"() {
        given:
        def redirectData = Mock(RedirectData)

        when:
        relyingPartyHandler.storeAndSetCookie(redirectData, redirectDataStorage, RelyingPartyHandler.REDIRECT_COOKIE_NAME)

        then:
        2 * redirectData.cookieId >> "cookieId"
        1 * redirectDataStorage.storeData("cookieId", redirectData)
        1 * ssoConfig.redirectUri >> new URI("http://localhost")
        1 * muleMessage.setOutboundProperty(_, _)
    }

    def "save token data in storage and set cookie"() {
        given:
        def tokenData = Mock(TokenData)

        when:
        relyingPartyHandler.storeAndSetCookie(tokenData, tokenStorage, relyingPartyHandler.TOKEN_COOKIE_NAME)

        then:
        2 * tokenData.cookieId >> "cookieId"
        1 * tokenStorage.storeData("cookieId", tokenData)
        1 * ssoConfig.redirectUri >> new URI("http://localhost")
        1 * muleMessage.setOutboundProperty(_, _)
    }

    def "configure http redirection in mule message"() {
        given:
        def uri = new URI("http://localhost")

        when:
        relyingPartyHandler.redirectToUri(uri)

        then:
        1 * muleMessage.setOutboundProperty("http.status", 302)
        1 * muleMessage.setOutboundProperty("http.reason", "Moved Temporarily")
        1 * muleMessage.setOutboundProperty("Location", uri)
    }

    def "extract cookie string"() {
        setup:
        def redirectCookieName = RelyingPartyHandler.REDIRECT_COOKIE_NAME
        def tokenCookieName = RelyingPartyHandler.TOKEN_COOKIE_NAME

        expect:
        relyingPartyHandler.cookieExtractor(cookieHeader, redirectCookieName) == "redirectCookie"
        relyingPartyHandler.cookieExtractor(cookieHeader, tokenCookieName) == "tokenCookie"
        relyingPartyHandler.cookieExtractor(cookieHeader, "someName") == null
        relyingPartyHandler.cookieExtractor(null, null) == null
    }
}