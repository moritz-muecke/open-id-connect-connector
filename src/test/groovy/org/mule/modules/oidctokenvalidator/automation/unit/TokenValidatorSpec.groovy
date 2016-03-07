package org.mule.modules.oidctokenvalidator.automation.unit

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import net.minidev.json.JSONObject
import org.mule.modules.oidctokenvalidator.automation.unit.util.RSAKeyGenerator
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenValidator
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenVerifier
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException
import spock.lang.Specification

import java.security.interfaces.RSAPublicKey


/**
 * Created by moritz.moeller on 07.03.2016.
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
        def json = new JSONObject();
        json.put("iss", props.getProperty("sso-url"));
        json.put("exp", System.currentTimeMillis() + 10000);
        json.put("nbf", 0);
        def claims = JWTClaimsSet.parse(json);
        ssoConfig.rsaPublicKey >> (RSAPublicKey)RSAKeyGenerator.keyPairGenerator().getPublic()
        ssoConfig.ssoUri >> new URI("http://localhost:8080")
        tokenVerifier.verifyAccessToken(_, _, _) >> claims

        expect:
        tokenValidator.localTokenValidation(authHeader, ssoConfig) == claims
        tokenValidator.localTokenValidation(authHeader, ssoConfig).issuer == props.getProperty("sso-url")
    }

    def "local token validation throws TokenValidationException"() {
        given:
        def authHeader = props.getProperty("bearer-auth-header")
        ssoConfig.rsaPublicKey >> (RSAPublicKey)RSAKeyGenerator.keyPairGenerator().getPublic()
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
        tokenValidator.createTokenIntrospectionRequest(accessToken, ssoConfig).token == accessToken
        tokenValidator.createTokenIntrospectionRequest(accessToken, ssoConfig).endpointURI == new URI("http://localhost:8080/introspect")
    }

}