package org.mule.modules.singlesignonoidc.config;

import java.net.URI;


import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class OIDCProviderMetadataBuilder {
	
	private static Client client = ClientBuilder.newClient();
	
	public static OIDCProviderMetadata provideMetadataFromServer(URI providerURI, String configurationEndpoint) throws ParseException {
        URI metadataURI = uriBuilder(providerURI, configurationEndpoint);
        return OIDCProviderMetadata.parse(requestJsonString(metadataURI));
	}
	
	public static OIDCProviderMetadata provideMetadataManually(URI ssoUri, String authEndpoint, String tokenEndpoint, String jwkSetEndpoint) {
        Issuer issuer = new Issuer(ssoUri);
        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
        OIDCProviderMetadata metaData = new OIDCProviderMetadata(issuer, subjectTypes, uriBuilder(ssoUri, jwkSetEndpoint));
        metaData.setAuthorizationEndpointURI(uriBuilder(ssoUri, authEndpoint));
        metaData.setTokenEndpointURI(uriBuilder(ssoUri, tokenEndpoint));
        metaData.applyDefaults();
        return metaData;
	}
	
	public static RSAPublicKey providePublicKey(OIDCProviderMetadata providerMetadata) throws ParseException, JOSEException, java.text.ParseException {
		URI jwkSetUri = providerMetadata.getJWKSetURI();
        String metaDataString = requestJsonString(jwkSetUri);
        // Parse the data as json
        JSONObject json = JSONObjectUtils.parse(metaDataString);
        // Find the RSA signing key
        JSONArray keyList = (JSONArray) json.get("keys");
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
                return RSAKey.parse(k).toRSAPublicKey();
            }
        }
        return null;
	}
	
	private static URI uriBuilder(URI uri, String path) {
		UriBuilder builder = UriBuilder.fromUri(uri).path(path);
        return builder.build();
	}
	
	private static String requestJsonString(URI uri) {
		WebTarget webTarget = client.target(uri);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON_TYPE);
        Response response = invocationBuilder.get();
        return response.readEntity(String.class);
	}
}
