package org.mule.modules.openidconnect.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import com.nimbusds.oauth2.sdk.ParseException;

/**
 * Created by moritz.moeller on 30.03.2016.
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
