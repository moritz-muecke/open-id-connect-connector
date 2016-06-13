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
package org.mule.modules.openidconnect.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

/**
 * A utility class which wraps and provides static method calls from the nimbus OpenIDConnect and OAuth2 SDK. Helps
 * to keep spock specs clean
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class NimbusParserUtil {

    public SignedJWT parseSignedJWT(String value) throws java.text.ParseException {
        return SignedJWT.parse(value);
    }

    public JWT parseJWT(String value) throws java.text.ParseException {
        return JWTParser.parse(value);
    }

    public AccessToken parseAccessToken(String authHeader) throws ParseException {
        return AccessToken.parse(authHeader);
    }

    public TokenIntrospectionResponse parseIntrospectionResponse(HTTPResponse response) throws ParseException {
        return TokenIntrospectionResponse.parse(response);
    }

    public TokenResponse parseTokenResponse(HTTPResponse response) throws ParseException {
        return OIDCTokenResponseParser.parse(response);
    }
}
