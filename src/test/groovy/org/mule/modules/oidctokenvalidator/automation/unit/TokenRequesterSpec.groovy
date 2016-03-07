package org.mule.modules.oidctokenvalidator.automation.unit

import com.google.gson.JsonObject
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.TokenResponse
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import net.minidev.json.JSONObject
import org.mule.modules.oidctokenvalidator.client.relyingparty.TokenRequestFactory
import org.mule.modules.oidctokenvalidator.client.relyingparty.TokenRequester
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig
import spock.lang.Specification


/**
 * Created by moritz.moeller on 07.03.2016.
 */
class TokenRequesterSpec extends Specification {
    def tokenRequestFactory = Mock(TokenRequestFactory)
    def ssoConfig = Mock(SingleSignOnConfig)
    def tokenRequester = new TokenRequester()
    def jsonResponse = new JSONObject()

    def setup(){
        tokenRequester.setTokenRequestFactory(tokenRequestFactory)
        ssoConfig.redirectUri >> new URI("http://localhost:8081")
        jsonResponse.put("access_token", "eyJhbGciOiJSUzI1NiJ9")
        jsonResponse.put("expires_in", 300)
        jsonResponse.put("refresh_expires_in", 1800)
        jsonResponse.put("refresh_token", "eyJhbGciOiJSUzI1NiJ9")
        jsonResponse.put("token_type", "bearer")
        jsonResponse.put("id_token", "eyJhbGciOiJSUzI1NiJ9")
        jsonResponse.put("not-before-policy", 0)
        jsonResponse.put("session-state", "f4fb5f23")

    }

    def "build valid redirect request"() {
        setup:
        def clientSecretBasic = new ClientSecretBasic(new ClientID("clientId"), new Secret("clientSecret"))
        def providerMetaData = Mock(OIDCProviderMetadata)
        providerMetaData.authorizationEndpointURI >> new URI("http://localhost:8080/auth")
        ssoConfig.clientSecretBasic  >> clientSecretBasic
        ssoConfig.providerMetadata >> providerMetaData

        expect:
        tokenRequester.buildRedirectRequest(ssoConfig).clientID.value == "clientId"
        tokenRequester.buildRedirectRequest(ssoConfig).redirectionURI.toString() == "http://localhost:8081"
        tokenRequester.buildRedirectRequest(ssoConfig).toURI().toString().startsWith("http://localhost:8080/auth?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8081&scope=openid")
    }
}