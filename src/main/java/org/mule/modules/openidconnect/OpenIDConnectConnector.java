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
package org.mule.modules.openidconnect;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Password;
import org.mule.api.annotations.lifecycle.OnException;
import org.mule.api.annotations.lifecycle.Start;
import org.mule.api.annotations.param.Default;
import org.mule.api.callback.SourceCallback;
import org.mule.api.store.ListableObjectStore;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.modules.openidconnect.client.OpenIdConnectClient;
import org.mule.modules.openidconnect.client.relyingparty.RelyingPartyHandler;
import org.mule.modules.openidconnect.client.relyingparty.TokenRequester;
import org.mule.modules.openidconnect.client.relyingparty.storage.RedirectData;
import org.mule.modules.openidconnect.client.relyingparty.storage.Storage;
import org.mule.modules.openidconnect.client.relyingparty.storage.TokenData;
import org.mule.modules.openidconnect.client.tokenvalidation.TokenValidator;
import org.mule.modules.openidconnect.client.tokenvalidation.TokenVerifier;
import org.mule.modules.openidconnect.config.ConnectorConfig;
import org.mule.modules.openidconnect.config.SingleSignOnConfig;
import org.mule.modules.openidconnect.exception.ExceptionHandler;
import org.mule.modules.openidconnect.exception.MetaDataInitializationException;
import org.mule.modules.openidconnect.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

/**
 * This connector is used to filter invalid requests by validating bearer tokens obtained from the http 'Authorization'
 * header or to act as an OpenID Connect relying party.
 * You can choose between local token validation and online token validation by token introspection. Online means you
 * have to configure the introspection endpoint of your identity provider. Tokens will then be validated via the http
 * introspection endpoint. Validates issuer, if token is active and verifies the signature.
 *
 * If the connector acts as relying party, you will need an id and a secret for this client, registered at the identity
 * provider.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
@Connector(name="open-id-connect", friendlyName="OpenID Connect",minMuleVersion = "3.6.1", description = "OpenID Connect Module")
public class OpenIDConnectConnector {

	private OpenIdConnectClient client;
    private SingleSignOnConfig ssoConfig;
    private static final String HTTP_STATUS = HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY;

    private static final Logger logger = LoggerFactory.getLogger(OpenIDConnectConnector.class);

	@Config
    ConnectorConfig config;

    @Inject
    MuleContext muleContext;

    @Start
    public void init() throws MetaDataInitializationException, ObjectStoreException {
        logger.debug("Initializing OpenIDConnect Connector");
        ssoConfig = new SingleSignOnConfig(config);
        try {
            logger.debug("Building Identity-Provider metadata");
            ssoConfig.buildProviderMetadata();
        } catch (MetaDataInitializationException e) {
            logger.error(e.getMessage());
        }
        TokenVerifier verifier = new TokenVerifier();
        TokenValidator validator = new TokenValidator(verifier);
        logger.debug("Instantiating client");
        client = new OpenIdConnectClient(ssoConfig, validator);
    }
        
    /**
     * Uses token introspection specified by OAUTH 2.0 to validate the token. It calls an api endpoint at the sso with
     * the given bearer token from the request header. Throws exception handled by ExceptionHandler if token isn't
     * valid or if there are connection problems with the sso, otherwise it continues processing. If claim extraction
     * is activated, set of id-token claims is added to the flow variables.
     * 
     * {@sample.xml ../../../doc/open-id-connect.xml.sample open-id-connect:online-token-validation}
     *
     * @param muleEvent injected by devkit
     * @param tokenHeader Header with token to be validated ('Bearer TOKEN_STRING')
     * @param introspectionEndpoint The path of the introspection endpoint
     * @param clientId Any Client-ID from the SSO to prevent token scanning attacks
     * @param clientSecret The Secret of the given Client-ID
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @OnException(handler = ExceptionHandler.class)
    @Processor
    public void onlineTokenValidation(
    		MuleEvent muleEvent,
            @Default("#[message.inboundProperties.'Authorization']")String tokenHeader,
    		String introspectionEndpoint,
    		@FriendlyName("Client ID")String clientId,
            @Password String clientSecret,
            @Default("false") boolean claimExtraction) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        ssoConfig.setIntrospectionUri(UriBuilder.fromUri(ssoConfig.getSsoUri()).path(introspectionEndpoint).build());
        ssoConfig.setClientSecretBasic(new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)));

        if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
        logger.debug("Starting token introspection via identity provider");
        Map<String, Object> claims = client.ssoTokenValidation(tokenHeader);
        if (claimExtraction) {
            logger.debug("Saving token claims as flowVar tokenClaims");
            muleMessage.setInvocationProperty("tokenClaims", claims);
        }
    }


    /**
     * Uses token introspection specified by OAUTH 2.0 to validate the token. It calls an api endpoint at the sso with
     * the given bearer token from the request header. If token is valid the connector checks if the userId from
     * the token matches given userId. Throws exception handled by ExceptionHandler if token isn't valid or if there
     * are connection problems with the sso, otherwise it continues processing. If claim extraction is activated, set
     * of id-token claims is added to the flow variables.
     *
     * {@sample.xml ../../../doc/open-id-connect.xml.sample open-id-connect:online-token-validation-with-user-id}
     *
     * @param muleEvent injected by devkit
     * @param tokenHeader Header with token to be validated ('Bearer TOKEN_STRING')
     * @param introspectionEndpoint The path of the introspection endpoint
     * @param userId ID of the user the token was issued to
     * @param clientId Any Client-ID from the SSO to prevent token scanning attacks
     * @param clientSecret The Secret of the given Client-ID
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @OnException(handler = ExceptionHandler.class)
    @Processor
    public void onlineTokenValidationWithUserId(
            MuleEvent muleEvent,
            @Default("#[message.inboundProperties.'Authorization']")String tokenHeader,
            String introspectionEndpoint,
            String userId,
            @FriendlyName("Client ID")String clientId,
            @Password String clientSecret,
            @Default("false") boolean claimExtraction) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        ssoConfig.setIntrospectionUri(UriBuilder.fromUri(ssoConfig.getSsoUri()).path(introspectionEndpoint).build());
        ssoConfig.setClientSecretBasic(new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)));

        if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
        logger.debug("Starting token introspection via identity provider and matching userId");
        Map<String, Object> claims = client.ssoTokenValidation(tokenHeader);
        if(!claims.get("sub").equals(userId)) {
            throw new TokenValidationException("UserId does not match the token UserId");
        }
        if (claimExtraction) {
            logger.debug("Saving token claims as flowVar tokenClaims");
            muleMessage.setInvocationProperty("tokenClaims", claims);
        }
    }



    /**
     * Uses a internal class to validate the token. Throws an exception handled by ExceptionHandler if validation fails.
     * If claim extraction is activated, set of id-token claims is added to the flow variables.
     *
     * {@sample.xml ../../../doc/open-id-connect.xml.sample open-id-connect:local-token-validation}
     *
     * @param muleEvent The current MuleEvent Injected by the devkit
     * @param tokenHeader Header with token to be validated ('Bearer TOKEN_STRING')
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @OnException(handler = ExceptionHandler.class)
    @Processor
    public void localTokenValidation(
            MuleEvent muleEvent,
            @Default("#[message.inboundProperties.'Authorization']")String tokenHeader,
            @Default("false") boolean claimExtraction) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
        logger.debug("Starting token validation via connector");
        Map<String, Object> claims = client.localTokenValidation(tokenHeader);
        if (claimExtraction) {
            logger.debug("Saving token claims as flowVar tokenClaims");
            muleMessage.setInvocationProperty("tokenClaims", claims);
        }
    }


    /**
     * Uses a internal class to validate the token and the UserID the token was given to. Throws an exception handled
     * by ExceptionHandler if validation fails.
     * If claim extraction is activated, set of id-token claims is added to the flow variables.
     *
     * {@sample.xml ../../../doc/open-id-connect.xml.sample open-id-connect:local-token-validation-with-user-id}
     *
     * @param muleEvent The current MuleEvent Injected by the devkit
     * @param userId ID of the user the token was issued to
     * @param tokenHeader Header with token to be validated ('Bearer TOKEN_STRING')
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @OnException(handler = ExceptionHandler.class)
    @Processor
    public void localTokenValidationWithUserId(
            MuleEvent muleEvent,
            String userId,
            @Default("#[message.inboundProperties.'Authorization']")String tokenHeader,
            @Default("false") boolean claimExtraction) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
        logger.debug("Starting token validation with user id via connector");
        Map<String, Object> claims = client.localTokenValidation(tokenHeader);
        if(!claims.get("sub").equals(userId)) {
            throw new TokenValidationException("UserId does not match the token UserId");
        }
        if (claimExtraction) {
            logger.debug("Saving token claims as flowVar tokenClaims");
            muleMessage.setInvocationProperty("tokenClaims", claims);
        }
    }


    /**
     * With this processor the connector works as a relying party specified by the OpenID Connect standard. Token
     * management is realized via the mule object store. Redirects user to the identity provider if there isn't an
     * active session. Otherwise it enhances the request with the Authorization header and continues processing of the
     * current flow.
     *
     * {@sample.xml ../../../doc/open-id-connect.xml.sample open-id-connect:act-as-relying-party}
     *
     * @param callback injected by devkit
     * @param muleEvent injected by devkit
     * @param redirectUri URI which is registered at the Identity Provider
     * @param clientId SSO client ID for this application
     * @param clientSecret SSO client secret for this application
     * @param instantRefresh Specifies if the tokens are refreshed at every request or only if they expire
     * @return Intercepts the flow if redirecting or process with original content
     * @throws URISyntaxException If redirect URI isn't valid
     */
    @Processor(intercepting = true)
    public Object actAsRelyingParty(
            SourceCallback callback,
            MuleEvent muleEvent,
            String redirectUri,
            String clientId,
            @Password String clientSecret,
            @Default("false") boolean instantRefresh) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        ssoConfig.setRedirectUri(new URI(redirectUri));
        ssoConfig.setClientSecretBasic(clientSecretBasic);
        RelyingPartyHandler handler = initializeRelyingParty(muleMessage, instantRefresh);

        try {
            if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
            logger.debug("Handling request as relying party");
            client.actAsRelyingParty(handler);

            Set<String> outboundProps = muleMessage.getOutboundPropertyNames();
            if (outboundProps.contains(HTTP_STATUS) &&
                    (int)muleMessage.getOutboundProperty(HTTP_STATUS) == Response.Status.FOUND.getStatusCode()) {
                return muleMessage.getPayload();
            } else {
                logger.debug("Continue processing flow. Access granted");
                return callback.processEvent(muleEvent).getMessage().getPayload();
            }
        } catch (MetaDataInitializationException e) {
            changeResponseStatus(muleMessage, Response.Status.BAD_GATEWAY);
            muleMessage.setPayload("Could not connect to OpenID provider");
            logger.error(e.getMessage());
            return muleMessage.getPayload();
        } catch (Exception e) {
            changeResponseStatus(muleMessage, Response.Status.INTERNAL_SERVER_ERROR);
            logger.debug("Error while acting as relying party. Exception: {}. Reason: {}", e.getCause(), e.getMessage());
            muleMessage.setPayload("An error occurred: " + e.getMessage());
            return muleMessage.getPayload();
        }
    }

    /**
     * Helper method to change the status code and reason phrase of the current request/mule message
     *
     * @param message MuleMessage where HTTP status properties are changed
     * @param statusType HTTP status type which should be configured
     */
	private void changeResponseStatus(MuleMessage message, Response.StatusType statusType) {
		message.setOutboundProperty(
                HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY, statusType.getStatusCode()
        );
		message.setOutboundProperty(
                HttpConstants.ResponseProperties.HTTP_REASON_PROPERTY, statusType.getReasonPhrase()
        );
	}

    /**
     * Helper method to instantiate a RelyingPartyHandler
     *
     * @param muleMessage the current mule message
     * @param instantRefresh token set instant refresh
     * @return the relying party
     */
    private RelyingPartyHandler initializeRelyingParty(MuleMessage muleMessage, boolean instantRefresh){
        ListableObjectStore<TokenData> tokenStore = muleContext.getObjectStoreManager()
                .getObjectStore("token-cookie-store");
        Storage<TokenData> tStorage = new Storage<>(tokenStore);
        ListableObjectStore<RedirectData> redirectStore = muleContext.getObjectStoreManager()
                .getObjectStore("redirect-cookie-store");
        Storage<RedirectData> rStorage= new Storage<>(redirectStore);
        TokenRequester requester = new TokenRequester();
        TokenVerifier verifier = new TokenVerifier();
        return new RelyingPartyHandler(muleMessage, requester, tStorage, rStorage, ssoConfig, verifier, instantRefresh);
    }

    public ConnectorConfig getConfig() {
        return config;
    }

    public void setConfig(ConnectorConfig config) {
        this.config = config;
    }
    
    public OpenIdConnectClient getClient() {
		return client;
	}

	public void setClient(OpenIdConnectClient client) {
		this.client = client;
	}

    public MuleContext getMuleContext() {
        return muleContext;
    }

    public void setMuleContext(MuleContext muleContext) {
        this.muleContext = muleContext;
    }
}