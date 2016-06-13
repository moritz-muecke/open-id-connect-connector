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
package org.mule.modules.openidconnect.client.relyingparty;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;

import java.net.URI;

/**
 * Factory to build TokenRequest objects of the Nimbus OIDC OAuth2 SDK.
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class TokenRequestFactory {
    public TokenRequest getTokenRequest(
            URI endpoint,
            ClientAuthentication clientAuthentication,
            AuthorizationGrant authCodeGrant) {
        return new TokenRequest(endpoint, clientAuthentication, authCodeGrant);
    }
}
