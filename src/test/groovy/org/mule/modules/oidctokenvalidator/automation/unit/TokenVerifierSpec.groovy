package org.mule.modules.oidctokenvalidator.automation.unit

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator
import net.minidev.json.JSONObject
import org.mule.modules.oidctokenvalidator.automation.unit.util.RSAKeyGenerator
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenVerifier
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException
import spock.lang.Specification

import java.security.interfaces.RSAPublicKey


/**
 * Created by moritz.moeller on 08.03.2016.
 */
class TokenVerifierSpec extends Specification {

    def props = new Properties()
    def tokenVerifier = new TokenVerifier()

    def setup(){
        props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())))
    }

    def "verify valid refreshed id token"() {
        given:
        def currentIdToken = Mock(JWT)
        def newIdToken = Mock(JWT)
        def tokenClaims = [
                iss: "http:localhost:8080",
                sub: "id-123",
                aud: "http://localhost:8081",
                iat: System.currentTimeSeconds()
        ]
        def tokenJson = new JSONObject(tokenClaims)
        def currentJwtClaims = JWTClaimsSet.parse(tokenJson)
        def newJwtClaims = JWTClaimsSet.parse(tokenJson)

        when:
        tokenVerifier.verifyRefreshedIdToken(currentIdToken, newIdToken)

        then:
        1 * currentIdToken.getJWTClaimsSet() >> currentJwtClaims
        1 * newIdToken.getJWTClaimsSet() >> newJwtClaims
    }

    def "verify invalid refresh token and throw TokenValidationException"() {
        given:
        def currentIdToken = Mock(JWT)
        def newIdToken = Mock(JWT)
        def currentTokenClaims = [
                iss: "http://localhost:8080",
                sub: "id-123",
                aud: "http://localhost:8081",
                iat: System.currentTimeSeconds()
        ]
        def newTokenClaims = [
                iss: "http://otherhost:8080",
                sub: "id-456",
                aud: "http://otherhost:8081",
                iat: System.currentTimeSeconds()
        ]
        def currentTokenJson = new JSONObject(currentTokenClaims)
        def newTokenJson = new JSONObject(newTokenClaims)
        def currentJwtClaims = JWTClaimsSet.parse(currentTokenJson)
        def newJwtClaims = JWTClaimsSet.parse(newTokenJson)

        when:
        tokenVerifier.verifyRefreshedIdToken(currentIdToken, newIdToken)

        then:
        1 * currentIdToken.getJWTClaimsSet() >> currentJwtClaims
        1 * newIdToken.getJWTClaimsSet() >> newJwtClaims
        TokenValidationException e = thrown()
        e.message == "Refreshed ID token issuer doesn't match current issuer"
    }

    def "ensure access token is not active"() {
        setup:
        def accessToken = AccessToken.parse(props.getProperty('bearer-auth-header'))

        expect:
        !tokenVerifier.isActive(accessToken)
    }
}