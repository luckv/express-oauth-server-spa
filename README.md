# express-oauth-server-spa
An ouath2 server implementation for node.js and express, working with SPAs (Single Page Applications)
An example of client could be found [here](https://github.com/luckv/oauth-client-spa)

Use:
+ [express-oauth-server v2.0.0](https://github.com/oauthjs/express-oauth-server)
+ [node-oauth2-server v3.0.0](https://github.com/oauthjs/node-oauth2-server)

The module can be used only in ***https connections***. All cookies created have the `secure` flag enabled, making them disappear if you use plain http.

Fully supports only the *authorization code* grant as defined in [RFC 6749 section 4.1](https://tools.ietf.org/html/rfc6749#section-4.1). Other grant types may be added in future. Feel free to open an issue, make a pull request or email me if you want to collaborate.

## Module content

This module exposes one function `AuthorizationCodeServer()` that returns an object with these properties:
+ `router` of type [Router](http://expressjs.com/en/4x/api.html#router) contains all middleware for the authorization flow. It can be mounted on any path, so all endpoints defined in parameters are relative to where the router will be mounted. Can be mounted on more than one path, if you want.
+ `authenticate_middleware` The same as `authenticate()`, it's a middleware for express that handle authentication through the `Authorization` header.
+ `session_authenticate_middleware`  Try to authenticate using the access token saved in a cookie as `oauth2_token`. If the user agent accepts html and cookie is not found and/or the authorization flow is not yet completed, it completes the flow requesting authentication to user.
+ `errorHandler_middleware` Handle oauth client errors. Oauth client errors are the one caused by the client because there was a missed parameter, an invalid token or something else. It does not depends on bugs or failures of the system. If the user agent accepts html, may be sent a human readable response.

This module exposes one function that requires two parameters, the first are the options of the **express-oauth-server** as described in that package, the second is an object with the following parameters:

+ `serverPort` The port where the server will listen for incoming request. This does NOT imply that the module itself will create an https server and start listening on that port
+ `oauth_endpoints` An object with at  least two properties:
  + `token` The relative path where the server will listen as a token endpoint
  + `authorize` The relative path where the server will listen as an authorization endpoint
+ `authorizationCode_loginPage_path` The absolute path in the file system to the html file that contains authorization form (only username\password login for now)
+ `server_description_endpoint` If the server should expose `oauth_endpoints` at `./oauth_endpoints` .  *optional*

## Debug
There is debug information supplied with the [debug](https://www.npmjs.com/package/debug) npm package through three subchannels:
+ **express-oauth-server-spa:authorization-flow** Information about authorization and token endpoints
+ **express-oauth-server-spa:session-authenticate-middleware** Information of what happens inside `session_authenticate_middleware(req, res, next)`
+ **express-oauth-server-spa:error-handler** Information about handling oauth client errors

## Authorization form

When the user starts the authorization code flow, it is redirected to a login page, the page in `authorizationCode_loginPage_path`, where a script creates a cookie with authentication information and stores it in the cookie `oauth2_authorization_code_auth`. Then the url is reloaded, sending the cookie to the server which will use it to authenticate the user, redirect back to redirect uri and pass the authorization code in query parameters (see [RFC 6750 section 4.1.2](https://tools.ietf.org/html/rfc6749#section-4.1.2))

The cookie it's an object with the field `type` to indicate the type of authentication, and additional fields with the authentication data. For now the only supported type is `user` and the additional properties are `username` and `password`. If you don't use https during authentication, all these information could be sniffed and/or edited by someone listening the network traffic!
