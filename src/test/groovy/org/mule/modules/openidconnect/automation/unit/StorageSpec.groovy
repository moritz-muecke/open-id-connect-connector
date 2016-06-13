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

import org.mule.api.store.ObjectStore
import org.mule.modules.openidconnect.client.relyingparty.storage.Storage
import spock.lang.Specification


/**
 * Test specification for the Storage
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class StorageSpec extends Specification {
    def store = Mock(ObjectStore)
    def storage = new Storage(store)
    def key = "storageKey"
    def entry = "entry"


    def "store already consisting data in storage"() {
        when:
        storage.storeData(key, entry)

        then:
        1 * store.contains(key) >> true
        1 * store.remove(key)
        1 * store.store(key, entry)
    }

    def "store new data in storage"() {
        when:
        storage.storeData(key, entry)

        then:
        1 * store.contains(key) >> false
        0 * store.remove(key)
        1 * store.store(key, entry)
    }

    def "read existing data"() {
        setup:
        store.contains(key) >> true
        store.retrieve(key) >> entry

        expect:
        storage.getData(key) == entry
    }

    def "read non existing data"() {
        when:
        storage.getData(key)

        then:
        1 * store.contains(key) >> false
        0 * store.retrieve(key)
        storage.getData(key) == null
    }

    def "check if storage contains existing data"() {
        setup:
        store.contains(key) >> true

        expect:
        storage.containsData(key)
    }

    def "check if storage contains non existing data"() {
        setup:
        store.contains(key) >> false

        expect:
        !storage.containsData(key)
    }

    def "remove existing data"() {
        when:
        storage.removeData(key)

        then:
        1 * store.contains(key) >> true
        1 * store.remove(key)
    }

    def "remove non existing data"() {
        when:
        storage.removeData(key)

        then:
        1 * store.contains(key) >> false
        0 * store.remove(key)
    }
}