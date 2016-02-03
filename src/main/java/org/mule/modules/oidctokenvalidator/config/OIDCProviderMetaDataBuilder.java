package org.mule.modules.oidctokenvalidator.config;

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

public class OIDCProviderMetaDataBuilder {
	
	private Client client;
	private URI providerUri;
	
	public OIDCProviderMetaDataBuilder(URI providerUri) {
		this.providerUri = providerUri;
		client = ClientBuilder.newClient();
	}
	
	public OIDCProviderMetadata provideMetadataFromServer(String configurationEndpoint) throws ParseException {
        URI metadataURI = uriBuilder(providerUri, configurationEndpoint);
        return OIDCProviderMetadata.parse(requestJsonString(metadataURI));
	}
	
	public OIDCProviderMetadata provideMetadataManually(String authEndpoint, String tokenEndpoint, String jwkSetEndpoint) {
        Issuer issuer = new Issuer(providerUri);
        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
        OIDCProviderMetadata metaData = new OIDCProviderMetadata(issuer, subjectTypes, uriBuilder(providerUri, jwkSetEndpoint));
        metaData.setAuthorizationEndpointURI(uriBuilder(providerUri, authEndpoint));
        metaData.setTokenEndpointURI(uriBuilder(providerUri, tokenEndpoint));
        metaData.applyDefaults();
        return metaData;
	}
	
	public RSAPublicKey providePublicKey(OIDCProviderMetadata providerMetadata) throws ParseException, JOSEException, java.text.ParseException {
		URI jwkSetUri = providerMetadata.getJWKSetURI();
        String metaDataResponse = requestJsonString(jwkSetUri);
        JSONObject json = JSONObjectUtils.parse(metaDataResponse);
        RSAPublicKey publicKey = null;
        JSONArray keyList = (JSONArray) json.get("keys");
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
                publicKey = RSAKey.parse(k).toRSAPublicKey();
            }
        }
        return publicKey;
	}
	
	private URI uriBuilder(URI uri, String path) {
		UriBuilder builder = UriBuilder.fromUri(uri).path(path);
        return builder.build();
	}
	
	private String requestJsonString(URI uri) {
		WebTarget webTarget = client.target(uri);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON_TYPE);
        Response response = invocationBuilder.get();
        return response.readEntity(String.class);
	}
}
