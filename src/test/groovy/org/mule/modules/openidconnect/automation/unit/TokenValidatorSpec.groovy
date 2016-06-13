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

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import net.minidev.json.JSONObject
import org.mule.modules.openidconnect.automation.unit.util.RSAKeyGenerator
import org.mule.modules.openidconnect.client.NimbusParserUtil
import org.mule.modules.openidconnect.client.tokenvalidation.TokenValidator
import org.mule.modules.openidconnect.client.tokenvalidation.TokenVerifier
import org.mule.modules.openidconnect.config.SingleSignOnConfig
import org.mule.modules.openidconnect.exception.TokenValidationException
import spock.lang.Specification

import java.security.interfaces.RSAPublicKey


/**
 * Test specification for the TokenValidator
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class TokenValidatorSpec extends Specification {

    def props = new Properties()
    def tokenVerifier = Mock(TokenVerifier)
    def tokenValidator = new TokenValidator(tokenVerifier)
    def ssoConfig = Mock(SingleSignOnConfig)


    def setup(){
        props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())))
    }

    def "local token validation returns claim set"() {
        setup:
        def authHeader = props.getProperty("bearer-auth-header")
        def json = new JSONObject()
        json.put("iss", props.getProperty("sso-url"))
        json.put("exp", System.currentTimeMillis() + 10000)
        json.put("nbf", 0)
        def claims = JWTClaimsSet.parse(json)
        ssoConfig.rsaPublicKey >> (RSAPublicKey)RSAKeyGenerator.keyPairGenerator().public
        ssoConfig.ssoUri >> new URI("http://localhost:8080")
        tokenVerifier.verifyAccessToken(_, _, _) >> claims

        expect:
        tokenValidator.localTokenValidation(authHeader, ssoConfig) == claims
        tokenValidator.localTokenValidation(authHeader, ssoConfig).issuer == props.getProperty("sso-url")
    }

    def "local token validation throws TokenValidationException"() {
        given:
        def authHeader = props.getProperty("bearer-auth-header")
        ssoConfig.rsaPublicKey >> (RSAPublicKey)RSAKeyGenerator.keyPairGenerator().public
        ssoConfig.ssoUri >> new URI("http://localhost:8080")
        tokenVerifier.verifyAccessToken(_, _, _) >> {
            throw new TokenValidationException("Token validation failed")
        }

        when:
        tokenValidator.localTokenValidation(authHeader, ssoConfig)

        then:
        TokenValidationException exception = thrown()
        exception.message == "Token validation failed"
    }

    def "create token introspection request"() {
        setup:
        def accessToken = Mock(AccessToken)
        ssoConfig.introspectionUri >> new URI("http://localhost:8080/introspect")
        ssoConfig.clientSecretBasic >> new ClientSecretBasic(new ClientID("clientId"), new Secret("clientSecret"))

        expect:
        assert tokenValidator.createTokenIntrospectionRequest(accessToken, ssoConfig) instanceof TokenIntrospectionRequest
        tokenValidator
                .createTokenIntrospectionRequest(accessToken, ssoConfig).token == accessToken
        tokenValidator
                .createTokenIntrospectionRequest(accessToken, ssoConfig)
                .endpointURI == new URI("http://localhost:8080/introspect")
    }

    def "token introspection returns valid jsonobject"(){
        setup:
        def validator = Spy(TokenValidator)
        def header = "header"
        def parser = Mock(NimbusParserUtil)
        validator.setParser(parser)
        def accessToken = Mock(AccessToken)
        parser.parseAccessToken(header) >> accessToken
        def introspectionRequest = Mock(TokenIntrospectionRequest)
        validator.createTokenIntrospectionRequest(_, _) >> introspectionRequest
        def httpRequest = Mock(HTTPRequest)
        def httpResponse = new HTTPResponse(200)
        introspectionRequest.toHTTPRequest() >> httpRequest
        httpRequest.send() >> httpResponse
        def introspectionResponse = Mock(TokenIntrospectionSuccessResponse)
        parser.parseIntrospectionResponse(httpResponse) >> introspectionResponse
        def json = new JSONObject()
        json.put("active", true)
        introspectionResponse.toJSONObject() >> json

        expect:
        validator.introspectionTokenValidation(header, ssoConfig).get("active") == true
    }

    def "token introspection throws TokenValidationException"() {
        given:
        def validator = Spy(TokenValidator)
        def header = "header"
        def parser = Mock(NimbusParserUtil)
        validator.setParser(parser)
        def accessToken = Mock(AccessToken)
        parser.parseAccessToken(header) >> accessToken
        def introspectionRequest = Mock(TokenIntrospectionRequest)
        validator.createTokenIntrospectionRequest(_, _) >> introspectionRequest
        def httpRequest = Mock(HTTPRequest)
        def httpResponse = new HTTPResponse(200)
        introspectionRequest.toHTTPRequest() >> httpRequest
        httpRequest.send() >> httpResponse
        def introspectionResponse = Mock(TokenIntrospectionErrorResponse)
        parser.parseIntrospectionResponse(httpResponse) >> introspectionResponse

        when:
        validator.introspectionTokenValidation(header, ssoConfig).get("active") == true

        then:
        TokenValidationException e = thrown()
        assert e instanceof  TokenValidationException
    }

}