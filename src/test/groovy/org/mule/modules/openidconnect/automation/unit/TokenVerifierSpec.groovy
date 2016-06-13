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
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.AccessToken
import net.minidev.json.JSONObject
import org.mule.modules.openidconnect.client.NimbusParserUtil
import org.mule.modules.openidconnect.client.tokenvalidation.TokenVerifier
import org.mule.modules.openidconnect.exception.TokenValidationException
import spock.lang.Specification

import java.security.interfaces.RSAPublicKey


/**
 * Test specification for the TokenVerifier
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class TokenVerifierSpec extends Specification {

    def props = new Properties()
    def tokenVerifier = new TokenVerifier()
    def parser = Mock(NimbusParserUtil)

    def setup(){
        props.load(new FileReader(new File(this.getClass().getResource("unittest.properties").getPath())))
    }

    def "verify access token returns claims set"() {
        setup:
        def publicKey = Mock(RSAPublicKey)
        def verifier = Spy(TokenVerifier)
        verifier.setParser(parser)
        def origin = "origin"
        def accessToken = Mock(AccessToken)
        accessToken.getValue() >> _
        def signedJWT = Mock(SignedJWT)
        parser.parseSignedJWT(_) >> signedJWT
        def claims = JWTClaimsSet.parse('{"iss": "origin"}')
        signedJWT.getJWTClaimsSet() >> claims
        claims.issuer >> origin
        signedJWT.verify(_) >> true
        verifier.isActive(_) >> true

        expect:
        def claimsSet = verifier.verifyAccessToken(accessToken, publicKey, origin)
        claimsSet.issuer == origin
    }

    def "verify access token throws TokenValidationException"() {
        given:
        def publicKey = Mock(RSAPublicKey)
        def verifier = Spy(TokenVerifier)
        verifier.setParser(parser)
        def origin = "origin"
        def accessToken = Mock(AccessToken)
        accessToken.getValue() >> _
        def signedJWT = Mock(SignedJWT)
        parser.parseSignedJWT(_) >> signedJWT
        def claims = JWTClaimsSet.parse('{"iss": "origin"}')
        signedJWT.getJWTClaimsSet() >> claims
        claims.issuer >> origin
        signedJWT.verify(_) >> true
        verifier.isActive(_) >> false

        when:
        verifier.verifyAccessToken(accessToken, publicKey, origin)

        then:
        TokenValidationException e = thrown()
        assert e instanceof TokenValidationException
        e.message == "Token isn't active"
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

    def "verify invalid refreshed id token and throw TokenValidationException"() {
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