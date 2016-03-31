package org.mule.modules.openidconnect.automation.unit

import com.nimbusds.oauth2.sdk.TokenErrorResponse
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.http.CommonContentTypes
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.mule.modules.openidconnect.client.NimbusParserUtil
import org.mule.modules.openidconnect.client.relyingparty.TokenRequestFactory
import org.mule.modules.openidconnect.client.relyingparty.TokenRequester
import org.mule.modules.openidconnect.client.relyingparty.storage.TokenData
import org.mule.modules.openidconnect.config.SingleSignOnConfig
import org.mule.modules.openidconnect.exception.RequestTokenFromSsoException
import spock.lang.Specification


/**
 * Test specification for the TokenRequester
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class TokenRequesterSpec extends Specification {
    def tokenRequestFactory = Mock(TokenRequestFactory)
    def ssoConfig = Mock(SingleSignOnConfig)
    def parser = Mock(NimbusParserUtil)
    def tokenRequester = new TokenRequester()
    def clientSecretBasic = new ClientSecretBasic(new ClientID("client"), new Secret("secret"))
    def metaData = Mock(OIDCProviderMetadata)

    def setup(){
        tokenRequester.setTokenRequestFactory(tokenRequestFactory)
        tokenRequester.setParser(parser)
        ssoConfig.redirectUri >> new URI("http://localhost:8081")
        ssoConfig.getProviderMetadata() >> metaData
        metaData.getTokenEndpointURI() >> new URI("localhost:8080")
        ssoConfig.getClientSecretBasic() >> clientSecretBasic
    }

    def "build valid redirect request"() {
        setup:
        metaData.authorizationEndpointURI >> new URI("http://localhost:8080/auth")

        expect:
        tokenRequester.buildRedirectRequest(ssoConfig).clientID.value == "client"
        tokenRequester.buildRedirectRequest(ssoConfig).redirectionURI.toString() == "http://localhost:8081"
        tokenRequester.buildRedirectRequest(ssoConfig).toURI().toString().startsWith("http://localhost:8080/auth?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A8081&scope=openid")
    }

    def "request tokens from sso"() {
        setup:
        def tokenRequest = Mock(TokenRequest)
        def httpRequest = Mock(HTTPRequest)
        def tokensJson = new File(this.getClass().getResource("testtokenresponse.json").getPath()).text
        def httpResponse = Mock(HTTPResponse)
        def http = new HTTPResponse(200)
        http.setContentType(CommonContentTypes.APPLICATION_JSON)
        http.setContent(tokensJson)
        def tokenResponse = OIDCTokenResponse.parse(http)
        tokenRequestFactory.getTokenRequest(_, _, _) >> tokenRequest
        tokenRequest.toHTTPRequest() >> httpRequest
        httpRequest.send() >> httpResponse
        parser.parseTokenResponse(httpResponse) >> tokenResponse

        expect:
        def tokenData = tokenRequester.requestTokensFromSso("authCode123", ssoConfig)
        tokenData.accessToken != null
        tokenData.idToken != null
        tokenData.refreshToken != null
    }

    def "request tokens from sso throws RequestTokenFromSsoException"() {
        given:
        def tokenRequest = Mock(TokenRequest)
        def httpRequest = Mock(HTTPRequest)
        def httpResponse = Mock(HTTPResponse)
        def tokenErrorResponse = Mock(TokenErrorResponse)
        tokenRequestFactory.getTokenRequest(_, _, _) >> tokenRequest
        tokenRequest.toHTTPRequest() >> httpRequest
        httpRequest.send() >> httpResponse
        parser.parseTokenResponse(httpResponse) >> tokenErrorResponse

        when:
        tokenRequester.requestTokensFromSso("authCode123", ssoConfig)

        then:
        RequestTokenFromSsoException e = thrown()
        assert e instanceof RequestTokenFromSsoException
    }


    def "refresh token set"() {
        setup:
        def tokenData = Mock(TokenData)
        def tokensJson = new File(this.getClass().getResource("testtokenresponse.json").getPath()).text
        def http = new HTTPResponse(200)
        http.setContentType(CommonContentTypes.APPLICATION_JSON)
        http.setContent(tokensJson)
        def tokenResponse = OIDCTokenResponse.parse(http)
        def refreshToken = tokenResponse.OIDCTokens.refreshToken
        tokenData.getRefreshToken() >> refreshToken
        tokenData.getCookieId() >> "id"
        def httpResponse = Mock(HTTPResponse)
        def httpRequest = Mock(HTTPRequest)
        def tokenRequest = Mock(TokenRequest)
        tokenRequest.toHTTPRequest() >> httpRequest
        httpRequest.send() >> httpResponse
        tokenRequestFactory.getTokenRequest(_, _, _) >> tokenRequest
        parser.parseTokenResponse(httpResponse) >> tokenResponse

        expect:
        def refreshedTokenData = tokenRequester.refreshTokenSet(tokenData, ssoConfig)
        refreshedTokenData.accessToken != null
        refreshedTokenData.idToken != null
        refreshedTokenData.refreshToken != null
    }

    def "refresh token set throws RequestTokenFromSsoException"() {
        given:
        def tokenData = Mock(TokenData)
        def tokensJson = new File(this.getClass().getResource("testtokenresponse.json").getPath()).text
        def http = new HTTPResponse(200)
        http.setContentType(CommonContentTypes.APPLICATION_JSON)
        http.setContent(tokensJson)
        def tokenResponse = OIDCTokenResponse.parse(http)
        def refreshToken = tokenResponse.OIDCTokens.refreshToken
        tokenData.getRefreshToken() >> refreshToken
        tokenData.getCookieId() >> "id"
        def tokenRequest = Mock(TokenRequest)
        def httpRequest = Mock(HTTPRequest)
        tokenRequestFactory.getTokenRequest(_, _, _) >> tokenRequest
        tokenRequest.toHTTPRequest() >> httpRequest
        def httpResponse = Mock(HTTPResponse)
        httpRequest.send() >> httpResponse
        def tokenErrorResponse = Mock(TokenErrorResponse)
        parser.parseTokenResponse(httpResponse) >> tokenErrorResponse

        when:
        tokenRequester.refreshTokenSet(tokenData, ssoConfig)

        then:
        RequestTokenFromSsoException e = thrown()
        assert e instanceof RequestTokenFromSsoException
    }
}