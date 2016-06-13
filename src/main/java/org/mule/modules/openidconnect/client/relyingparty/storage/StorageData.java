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

import java.io.Serializable;
import java.util.UUID;

/**
 * Abstract class for the different data types stored in the Mule ObjectStore
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
public abstract class StorageData implements Serializable {
    String cookieId;

    StorageData() {
        this.cookieId = UUID.randomUUID().toString();
    }

    public String getCookieId() {
        return cookieId;
    }
}
