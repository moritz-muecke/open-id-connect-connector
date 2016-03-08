package org.mule.modules.oidctokenvalidator.automation.unit

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.mule.modules.oidctokenvalidator.config.OpenIDConnectMetaDataBuilder
import spock.lang.Specification



class OpenIdConnectMetaDataBuilderSpec extends Specification {
    def uri = new URI("http://localhost")
    def metaDataBuilder = Spy(OpenIDConnectMetaDataBuilder, constructorArgs: [uri])

    def "provide public key from json string"() {
        setup:
        def metaData = Mock(OIDCProviderMetadata)
        metaData.getJWKSetURI() >> new URI("http:localhost:8080/certs")
        metaDataBuilder.requestJsonString(_) >> new File(this.getClass().getResource('testkey.json').file).text

        expect:
        metaDataBuilder.providePublicKey(metaData) != null
        metaDataBuilder.providePublicKey(metaData).algorithm == "RSA"
    }
}