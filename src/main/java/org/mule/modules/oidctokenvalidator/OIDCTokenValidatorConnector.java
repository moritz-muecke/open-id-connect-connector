package org.mule.modules.oidctokenvalidator;

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
import org.mule.api.callback.SourceCallback;
import org.mule.api.store.ListableObjectStore;
import org.mule.api.store.ObjectStoreException;
import org.mule.module.http.api.HttpConstants;
import org.mule.modules.oidctokenvalidator.client.OpenIdConnectClient;
import org.mule.modules.oidctokenvalidator.client.relyingparty.RelyingPartyHandler;
import org.mule.modules.oidctokenvalidator.client.relyingparty.TokenRequester;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.RedirectData;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.Storage;
import org.mule.modules.oidctokenvalidator.client.relyingparty.storage.TokenData;
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenValidator;
import org.mule.modules.oidctokenvalidator.client.tokenvalidation.TokenVerifier;
import org.mule.modules.oidctokenvalidator.config.ConnectorConfig;
import org.mule.modules.oidctokenvalidator.config.SingleSignOnConfig;
import org.mule.modules.oidctokenvalidator.exception.HTTPConnectException;
import org.mule.modules.oidctokenvalidator.exception.MetaDataInitializationException;
import org.mule.modules.oidctokenvalidator.exception.TokenValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

/**
 * This connector is used to validate of bearer tokens obtained from the http 'Authorization' header
 * or to act as an OpenID Connect relying party.
 * You can choose between local token validation and online token validation by token introspection.
 * Online means you have to configure the introspection endpoint of your identity provider. Tokens
 * will then be validated via the http introspection endpoint. If the connector acts as relying party,
 * you will need an id and a secret for this client, registered on the identity provider side.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
@Connector(name="oidc-token-validator", friendlyName="OIDCTokenValidator")
public class OIDCTokenValidatorConnector {

	private OpenIdConnectClient client;
    private SingleSignOnConfig ssoConfig;
    private static final String HTTP_STATUS = HttpConstants.ResponseProperties.HTTP_STATUS_PROPERTY;

    private static final Logger logger = LoggerFactory.getLogger(OIDCTokenValidatorConnector.class);

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
     * the given bearer token from the request header. Intercepts the flow if token isn't valid, otherwise it continues
     * processing. If claim extraction is activated, set of id-token claims is added to the flow variables.
     * 
     * {@sample.xml ../../../doc/oidc-token-validator.xml.sample
	 * oidc-token-validator:online-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleEvent injected by devkit
     * @param introspectionEndpoint The path of the introspection endpoint
     * @param clientId Any Client-ID from the SSO to prevent token scanning attacks
     * @param clientSecret The Secret of the given Client-ID
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     * @throws HTTPConnectException if the identity provider is not available
     */
    @Processor(intercepting = true)
    public Object onlineTokenValidation(
    		SourceCallback callback,
    		MuleEvent muleEvent,
    		String introspectionEndpoint,
    		@FriendlyName("Client ID")String clientId,
            @Password String clientSecret,
    		boolean claimExtraction) throws HTTPConnectException {
        MuleMessage muleMessage = muleEvent.getMessage();
        ssoConfig.setIntrospectionUri(UriBuilder.fromUri(ssoConfig.getSsoUri()).path(introspectionEndpoint).build());
        ssoConfig.setClientSecretBasic(new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)));
        try {
            String authHeader = muleMessage.getInboundProperty(HttpHeaders.AUTHORIZATION);
    		logger.debug("Starting token introspection via identity provider");
            Map<String, Object> claims = client.ssoTokenValidation(authHeader);
			if (claimExtraction) {
                logger.debug("Saving token claims as flow var tokenClaims");
                muleMessage.setInvocationProperty("tokenClaims", claims);
			}
            muleMessage.setOutboundProperty(HttpHeaders.AUTHORIZATION, authHeader);
            return callback.processEvent(muleEvent).getMessage().getPayload();
		} catch (TokenValidationException e) {
            logger.debug("Token validation failed. Reason: {}. Interrupting flow now", e.getMessage());
            changeResponseStatus(muleMessage, Response.Status.UNAUTHORIZED);
            muleMessage.setOutboundProperty(
                    HttpHeaders.WWW_AUTHENTICATE, String.format("Error=\"%s\"", e.getMessage())
            );
            muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		} catch (HTTPConnectException e) {
            logger.debug("Could not connect to Identity Provider. Reason: {}. Interrupting flow now", e.getMessage());
            changeResponseStatus(muleMessage, Response.Status.SERVICE_UNAVAILABLE);
            muleMessage.setPayload(e.getMessage());
			throw e;
		} catch (Exception e) {
            logger.debug("Error during token introspection. Reason: {}. Interrupting flow now", e.getMessage());
            changeResponseStatus(muleMessage, Response.Status.BAD_REQUEST);
            muleMessage.setPayload(e.getMessage());
			return muleMessage.getPayload();
		}
    }
    
    
    /**
     * Uses a internal class to validate the token. Intercepts the flow if token isn't valid, otherwise it continues
     * processing. If claim extraction is activated, set of id-token claims is added to the flow variables.
     * 
     * {@sample.xml ../../../doc/oidc-token-validator.xml.sample
	 * oidc-token-validator:local-token-validation}
     * 
     * @param callback injected by devkit
     * @param muleEvent injected by devkit
     * @param claimExtraction Creates the FlowVar tokenClaims which contains a map with all claims of the given token
     * @return The original payload if token is valid. If not, flow is intercepted and responses to the caller
     */
    @Processor(intercepting = true)
    public Object localTokenValidation(SourceCallback callback, MuleEvent muleEvent, boolean claimExtraction) {
        MuleMessage muleMessage = muleEvent.getMessage();
        try {
            if (!ssoConfig.isInitialized()) ssoConfig.buildProviderMetadata();
            String authHeader = muleMessage.getInboundProperty(HttpHeaders.AUTHORIZATION);
            logger.debug("Starting token validation via connector");
            Map<String, Object> claims = client.localTokenValidation(authHeader);
            if (claimExtraction) {
                logger.debug("Saving token claims as flow var tokenClaims");
                muleMessage.setInvocationProperty("tokenClaims", claims);
            }
            muleMessage.setOutboundProperty(HttpHeaders.AUTHORIZATION, authHeader);
            return callback.processEvent(muleEvent).getMessage().getPayload();
        } catch (TokenValidationException e) {
            logger.debug("Token validation failed. Reason: {}. Interrupting flow now", e.getMessage());
            changeResponseStatus(muleMessage, Response.Status.UNAUTHORIZED);
            muleMessage.setOutboundProperty(
                    HttpHeaders.WWW_AUTHENTICATE, String.format("Error=\"%s\"", e.getMessage())
            );
            muleMessage.setPayload(e.getMessage());
            return muleMessage.getPayload();
        } catch (MetaDataInitializationException e) {
            changeResponseStatus(muleMessage, Response.Status.SERVICE_UNAVAILABLE);
            muleMessage.setPayload(e.getMessage());
            logger.error(e.getMessage());
            return muleMessage.getPayload();
        } catch (Exception e) {
            logger.debug("Error during token introspection. Reason: {}. Interrupting flow now", e.getMessage());
            changeResponseStatus(muleMessage, Response.Status.BAD_REQUEST);
            muleMessage.setPayload(e.getMessage());
            return muleMessage.getPayload();
        }
    }

    /**
     * With this processor the connector works as a relying party specified by the OpenID Connect standard. Token
     * management is realized via the mule object store. Redirects user to the identity provider if there isn't an
     * active session. Otherwise it enhances the request with the Authorization header and continues processing of the
     * current flow.
     *
     * {@sample.xml ../../../doc/oidc-token-validator.xml.sample
	 * oidc-token-validator:act-as-relying-party}
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
            boolean instantRefresh) throws Exception {
        MuleMessage muleMessage = muleEvent.getMessage();
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        ssoConfig.setRedirectUri(new URI(redirectUri));
        ssoConfig.setClientSecretBasic(clientSecretBasic);
        ListableObjectStore<TokenData> tokenStore = muleContext.getObjectStoreManager()
                .getObjectStore("token-cookie-store");
        Storage<TokenData> tokenStorage = new Storage<>(tokenStore);
        ListableObjectStore<RedirectData> redirectStore = muleContext.getObjectStoreManager()
                .getObjectStore("redirect-cookie-store");
        Storage<RedirectData> redirectStorage = new Storage<>(redirectStore);
        TokenRequester requester = new TokenRequester();
        TokenVerifier verifier = new TokenVerifier();
        RelyingPartyHandler handler = new RelyingPartyHandler(
                muleMessage,
                requester,
                tokenStorage,
                redirectStorage,
                ssoConfig,
                verifier,
                instantRefresh
        );

        try {
            logger.debug("Handling request as relying party");
            client.actAsRelyingParty(handler);

            Set<String> outboundProps = muleMessage.getOutboundPropertyNames();
            if (outboundProps.contains(HTTP_STATUS) &&
                    (int)muleMessage.getOutboundProperty(HTTP_STATUS) == Response.Status.FOUND.getStatusCode()) {
                logger.debug("Redirecting to identity provider");
                return muleMessage.getPayload();
            } else {
                logger.debug("Continue processing flow. Access granted");
                return callback.processEvent(muleEvent).getMessage().getPayload();
            }
        } catch (Exception e) {
            changeResponseStatus(muleMessage, Response.Status.INTERNAL_SERVER_ERROR);
            logger.debug("Error due acting as relying party. Exception: {}. Reason: {}", e.getCause(), e.getMessage());
            muleMessage.setPayload("An error occured: " + e.getMessage());
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