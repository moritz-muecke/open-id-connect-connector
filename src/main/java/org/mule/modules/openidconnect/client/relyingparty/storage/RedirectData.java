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
package org.mule.modules.openidconnect.client.relyingparty.storage;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.io.Serializable;
import java.util.UUID;

/**
 * Simple POJO to represent the redirect data saved in the Mule ObjectStore
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public class RedirectData extends StorageData {

    private Nonce nonce;
    private State state;
    private String jsonTokens;

    public RedirectData(Nonce nonce, State state) {
        this.nonce = nonce;
        this.state = state;
    }

    public Nonce getNonce() {
        return nonce;
    }

    public State getState() {
        return state;
    }

    public String getJsonTokens() {
        return jsonTokens;
    }

    public void setJsonTokens(String jsonTokens) {
        this.jsonTokens = jsonTokens;
    }

}
