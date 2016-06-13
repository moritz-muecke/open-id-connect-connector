# OpenID Connect Module for Mule
This connector offers validation of tokens issued by OpenID Connect and OAuth services. Invalid API Requests can be filtered right after entering mule. As an addition this connector can store, request and manage tokens issued by an OpenID Provider, to act as an OpenID Connect Relying Party.

# Main Features
The functionalities of this connector are split in two main features.

## Token Validation
Tokens can be validated in two ways, offline and online. Offline means the connector itself takes care of the validation. All necessary information about the token issuer like the URL or the public key e.g. have to be set in the connector configuration. With this information the connector is able to verify if the token is valid. If tokens are validated online, the connector itself just sends the token to the introspection endpoint of the OpenID Provider. This endpoint is specified by the OpenID Connect specification. After that the connector parses the response of the OpenID provider to tell if the token is valid or not. In both cases, the connector optional provides to validate the user id the token is issued to as well. In this case the id of the user has to be provided too. Without the user id the connector only validates the signature, the issuer and the expiration of the tokens.

## Relying Party
With relying party functionality the connector acts as an OpenID Connect client. In this case the client ID and secret has to be set in the connector configuration. After that the connector is able to store, request and manage tokens issued by the configured OpenID Provider. To do so the connector uses the Authorization Code Flow described by the OpenID Connect specification. Because HTTP redirects are necessary, this message processor is interrupting mule flows. Tokens are stored in memory in a mule object store on client side and in browser cookies on consumer side.

For detailed informations about features and usage please take a look at the [documentation](https://github.com/mrtzmllr/open-id-connect-connector/doc/user-manual.html).

# Additional Features
In addition to the features described above there are optional functionalities.

## Claim Extraction
The tokens used by OpenID Connect are [JSON Web Tokens](http://jwt.io). With token validation developers are able to activate claim extraction in the connector configuration. This means that key value pair set known as claims are extracted and saved as a flow variable. This variable named `tokenClaims` contains a map of all values. Mule developer can access all user data provided by the token immediately after it was validated.

## Configuration Discovery
As an extension of OpenID Connect Configuration Discovery specifies an endpoint at the OpenID Provider which provides all necessary informations to validate tokens. If the OpenID Provider used by this connector supports this feature, it is not necessary to configure all values manually. After starting the mule application the connector sends an HTTP request to the OpenID Provider and extracts it's configuration out of the response. This feature is optional. Configuration can also be set manually.

# Mule supported versions
Mule 3.6.1 and above

# Installation in Anypoint Studio and Usage
There is no public update site for this connector yet. You have to check out the project and perform an `mvn clean package`. This will generate an update-site which can be installed in Anypoint Studio via `Help -> Install New Software...`. Information about usage can be found in the [documentation](https://github.com/mrtzmllr/open-id-connect-connector/doc/user-manual.html).

# Reporting Issues
Use GitHub:Issues for tracking issues with this connector. You can report new issues at this link https://github.com/mrtzmllr/open-id-connect-connector/issues.
