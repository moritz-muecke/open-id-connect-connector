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
package org.mule.modules.openidconnect.automation.unit

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.mule.modules.openidconnect.config.MetaDataBuilder
import spock.lang.Specification


/**
 * Test specification for the MetaDataBuilder
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class MetaDataBuilderSpec extends Specification {
    def uri = new URI("http://localhost")
    def metaDataBuilder = Spy(MetaDataBuilder, constructorArgs: [uri])

    def "provide public key from json string"() {
        setup:
        def metaData = Mock(OIDCProviderMetadata)
        metaData.getJWKSetURI() >> new URI("http:localhost:8080/certs")
        metaDataBuilder.requestJsonString(_) >> new File(this.getClass().getResource('testkey.json').file).text

        expect:
        metaDataBuilder.providePublicKeyFromJwkSet(metaData) != null
        metaDataBuilder.providePublicKeyFromJwkSet(metaData).algorithm == "RSA"
    }
}