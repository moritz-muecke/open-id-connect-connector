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

/**
 * This class is responsible to build and provide meta data of an OpenID Connect
 * Identity-Provider. The data is provided manually with the parameters of the
 * ConnectorConfig or through HTTP from IdP. To obtain the configuration from
 * IdP the specified OpenID Configuration discovery is used.
 *
 * @author Moritz Möller, AOE GmbH
 * @see <a href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Connect spec</a>
 *
 */
public class OpenIDConnectMetaDataBuilder {
	
	private Client client;
	private URI providerUri;
	
	public OpenIDConnectMetaDataBuilder(URI providerUri) {
		this.providerUri = providerUri;
		client = ClientBuilder.newClient();
	}


    /**
     * Obtains the IdP configuration as JSON String via requestJsonString() to build and return the IdP-metadata
     *
     * @param configurationEndpoint Endpoint at the IdP to obtain configuration data
     * @return the IdP-metadata
     * @throws ParseException Thrown if the JSON from the response can not be parsed
     */
	public OIDCProviderMetadata provideMetadataFromServer(String configurationEndpoint) throws ParseException {
        URI metadataURI = uriBuilder(providerUri, configurationEndpoint);
        return OIDCProviderMetadata.parse(requestJsonString(metadataURI));
	}

    /**
     * Builds and returns the IdP-metadata manually from parameters passed to it.
     *
     * @param authEndpoint Authorization endpoint
     * @param tokenEndpoint Token endpoint
     * @param jwkSetEndpoint JSON Web Key endpoint
     * @return the IdP-metadata
     */
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

    /**
     * Parses a JSON string obtained from requestJsonString() to obtain the JSON Web Key configuration from the IdP
     * and returns the RSAPublicKey
     *
     * @param providerMetadata IdP metadata
     * @return The RSAPublicKey of the IdP
     * @throws ParseException
     * @throws JOSEException
     * @throws java.text.ParseException
     */
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

    /**
     * Helper method to extend and build URIs
     *
     * @param uri Base URI
     * @param path Path to be extend
     * @return New URI
     */
	private URI uriBuilder(URI uri, String path) {
		UriBuilder builder = UriBuilder.fromUri(uri).path(path);
        return builder.build();
	}

    /**
     * Requests JSON from given endpoint via HTTP and returns it as string
     *
     * @param uri Endpoint to obtain JSON from
     * @return JSON content as string
     */
	public String requestJsonString(URI uri) {
		WebTarget webTarget = client.target(uri);
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON_TYPE);
        Response response = invocationBuilder.get();
        return response.readEntity(String.class);
	}
}
