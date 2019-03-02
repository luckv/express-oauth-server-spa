
var Bluebird = require('bluebird');
var Router = require('express').Router;
var ExpressOAuthServer = require('express-oauth-server');
var OAuthServer = require('oauth2-server');
var utilFormat = require('util').format;
var URL = require('url').URL;
var qs = require('qs');
var httpsRequest = require('https').request;
var debug = require('debug');
var debugConsole = debug('express-oauth2-server-authorization-code');

var authorizationFlow_debug = debugConsole.extend('authorization-flow');
var sessionAuthenticate_debug = debugConsole.extend('session-authenticate-middleware');
var error_debug = debugConsole.extend('error-handler');


/**
 * Generate a random string of length exactly len
 * @param len {number}
 */
function generateRandomString(len) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < 5; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}

/**
 * Get the origin of a request
 * @param {express.Request} req
 * @returns {string}
 */
function getOrigin(req) {
    return req.protocol + "://" + req.get('host');
}

/**
 * Get the complete requested url of a request
 * @param {express.Request} req
 * @returns {string}
 */
function getHref(req) {
    return getOrigin(req) + req.originalUrl;
}

function isOauthClientError(err) {
    return err instanceof OAuthServer.OAuthError && !(err instanceof OAuthServer.ServerError) && !(err instanceof OAuthServer.InvalidArgumentError);
}

function OAuthServerMiddleware(oauthServer_options, oauth_endpoints, authorization_code_login_page_path, server_port) {
    this.oauth_server = new ExpressOAuthServer(oauthServer_options);
    this.oauth_server_options = oauthServer_options;
    this.oauth_endpoints = oauth_endpoints;
    this.authorization_code_login_page_path = authorization_code_login_page_path;
    this.server_port = server_port;

    this.authenticate = this.oauth_server.authenticate.bind(this.oauth_server);
    this.token = this.oauth_server.token.bind(this.oauth_server);
}

function authorize_html(req, res, next) {

    //Il codice del client non ha ancora creato il cookie con i dati di autenticazione
    if (!req.cookies.oauth2_authorization_code_auth) {

        authorizationFlow_debug("Cookie 'oauth2_authorization_code_auth' it's not present (user didn't authenticate)");

        //Il client sta facendo una richiesta di accedere ad un certo url (req.query.from_url) e non ha già cominciato il flow di autorizzazione dell'authentication code (!req.cookies.oauth2_authorization_code_init)
        if (req.query.from_url && !req.cookies.oauth2_authorization_code_init) {


            //Creo un cookie con i dati iniziali del processo di autenticazione
            //I parametri necessari a completare il processo di richiesta del token (redirect_uri e state)
            //L'url da cui è partito il processo di autenticazione (start_url). Punto di ritorno in caso di errori
            //L'url con cui effettuare la prima richiesta all'endpoint di autorizzazione (authorization_url). La richiesta a questo url segna l'inizio del processo di autenticazione nel protocollo oauth
            var auth_init = {
                redirect_uri: req.query.from_url,
                state: generateRandomString(5),
                start_url: getHref(req),
                authorization_url: undefined
            };

            {
                //Creo l'url per iniziare il flow di autenticazione
                const auth_queryParams = {
                    response_type: 'code',
                    client_id: 'web_client',
                    redirect_uri: auth_init.redirect_uri,
                    state: auth_init.state,
                    from_url: req.query.from_url
                }

                const auth_url = new URL(this.oauth_endpoints.authorization, getOrigin(req));
                //setSearchParams(auth_url, auth_queryParams);
                auth_url.search = qs.stringify(auth_queryParams);

                auth_init.authorization_url = auth_url.toString();
            }

            res.cookie('oauth2_authorization_code_init', auth_init, { httpOnly: true, sameSite: true, secure: true, maxAge: 600000 }); //maxAge = 10 minutes = 10 * 60 * 1000 ms

            //Eseguo un redirect, sull'endpoint di autorizzazione, con tutti i dati necessari nella query
            res.redirect(auth_init.authorization_url);
            authorizationFlow_debug("Created 'oauth2_authorization_code_init' cookie and redirected to authorization endpoint with oauth parameters to initialize authorization code flow\n%O\n%s", auth_init);

        }
        else {
            //Il client ha richiesto un url già predisposto per la prima parte del flow di autorizzazione dell'authentication code e quindi è necessario richiedere l'autorizzazione (autenticazione) dell'utente
            res.sendFile(this.authorization_code_login_page_path);
            authorizationFlow_debug("Sended authorization request page to client");
        }
    }
    else {
        //Il codice del client, fornito da questo server, ha creato il cookie con i dati di autenticazione, 
        //è quindi possibile lasciare agire il middleware di autorizzazione per rilasciare il codice di autorizzazione (authorization code)
        res.clearCookie('oauth2_authorization_code_auth');  //Elimino il cookie di con i dati di autenticazione dalla risposta del server, è ancora accessibile da req.cookies
        authorizationFlow_debug("Cookie 'oauth2_authorization_code_auth' deleted from response");
        authorizationFlow_debug("Cookie 'oauth2_authorization_code_auth' it's present (user authenticated), so we proceed to authentication middleware");
        next();
    }


}

OAuthServerMiddleware.prototype.authorize = function authorize() {
    return [
        authorize_html.bind(this),
        this.oauth_server.authorize({
            authenticateHandler: {
                handle: (function (req, res) {
                    //Da middleware precedente, è chiaro che si giunge in questo punto solo se il cookie con i dati di autenticazione è presente
                    const auth_cookie = req.cookies.oauth2_authorization_code_auth;
                    const user = this.oauth_server_options.model.getUser(auth_cookie.username, auth_cookie.password);
                    authorizationFlow_debug("authenticateHandler(): %O", user);
                    return user;
                }).bind(this),
            }
        })
    ];
}

/**
 * Make a local request to the token endpoint. Returns a promise that resolve with the access token, or reject with the error encountered (see https://tools.ietf.org/html/rfc6749#section-4.1.2)
 * @param {any} body of the token request see https://tools.ietf.org/html/rfc6749#section-4.1.3
 * @param {string} token_endpoint The relative token endpoint to the localhost
 * @returns {Bluebird<any>}
 */
function localTokenRequest(body, token_endpoint, port) {

    const options = {
        hostname: '127.0.0.1',
        port: port,
        path: token_endpoint,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        rejectUnauthorized: false,
    };

    return new Bluebird(function (resolve, reject) {

        var req = httpsRequest(options, function callback(httpRes) {
            //httpRes.setEncoding('utf8');
            // cumulate data
            var body = [];
            httpRes.on('data', function (chunk) {
                body.push(chunk);
            });

            // resolve on end
            httpRes.on('end', function () {
                try {
                    body = JSON.parse(Buffer.concat(body).toString());
                } catch (e) {
                    reject(e);
                    return;
                }

                if (body.error) {
                    //An error occured during access token request
                    // https://tools.ietf.org/html/rfc6749.html#section-4.1.2.1
                    const exceptionToThrow = (function parse_error() {
                        switch (body.error) {
                            case 'invalid_request': return OAuthServer.InvalidRequestError;
                            case 'unauthorized_client': return OAuthServer.UnauthorizedClientError;
                            case 'access_denied': return OAuthServer.AccessDeniedError;
                            case 'unsupported_response_type': return OAuthServer.UnsupportedResponseTypeError;
                            case 'invalid_scope': return OAuthServer.InvalidScopeError;
                            case 'server_error': return OAuthServer.ServerError;
                            case 'temporarily_unavailable': return OAuthServer.ServerError;
                        }
                    }
                    )();

                    reject(new exceptionToThrow(body.error_description));
                }
                else
                    resolve(body);
            });
        });

        req.on('error', function errorCallback(err) {
            reject(new OAuthServer.ServerError(err.message, err));
        })

        req.write(qs.stringify(body));
        req.end();
    })
        .tap((accessToken) => {
            sessionAuthenticate_debug("Successful access token request: %O", accessToken);
        })
        .tapCatch((err) => {
            if (isOauthClientError(err))
                sessionAuthenticate_debug("Denied access token request: %O", err);
            else
                sessionAuthenticate_debug("Error durying access token request: %O", err);
        });

}

function session_authenticate(req, res, next) {
    if (req.cookies.oauth2_token) {
        sessionAuthenticate_debug("Cookie with oauth token found\n%O", req.cookies.oauth2_token);
        //TODO: Need to retrieve token information, in the same way of oauth2 library 
        //TODO: May be the token is invalid. Throw InvalidTokenError
        //TODO: May be the scope is not sufficient to access the resource. Throw InsufficientScopeError
        res.locals.oauth = { token: req.cookies.oauth2_token }
        next();
    }
    else {
        const acceptsHtml = req.accepts('html');

        sessionAuthenticate_debug('query parameters - state = %s, code = %s', req.query.state, req.query.code);

        if (req.cookies.oauth2_authorization_code_init && req.query.state && req.query.code) {
            sessionAuthenticate_debug("Oauth flow initiated by this server, and url query parameters (state and code) are present");

            const auth_init = req.cookies.oauth2_authorization_code_init;
            if (auth_init.state === req.query.state) {

                sessionAuthenticate_debug("query parameter state it's the same created from the server. Retrieve access token");

                const body = {
                    grant_type: 'authorization_code',
                    code: req.query.code,
                    redirect_uri: auth_init.redirect_uri,
                    client_id: 'web_client'
                };

                //If there is an authorization code (req.query.code) and a state (req.query.state), it means that it's necessary to retrieve an access token
                localTokenRequest(body, this.oauth_endpoints.token, this.server_port)
                    .finally(() => {
                        //Remove all cookies about oauth2 authorization code flow, in any case
                        res.clearCookie('oauth2_authorization_code_init');
                        res.clearCookie('oauth2_authorization_code_auth');
                        sessionAuthenticate_debug("Cleared oauth cookies in response");
                    })
                    .then(oauth_token => {
                        //If token request is successful, then create a cookie with the access token, and call next handler, where protected content resides
                        res.locals.oauth = { token: oauth_token }
                        res.cookie('oauth2_token', oauth_token, { httpOnly: false, sameSite: true, secure: true });
                        sessionAuthenticate_debug("Created cookie 'oauth2_token' %O", oauth_token);
                        next();
                    })
                    .catch((err) => {
                        //An error occured during the token request
                        if (acceptsHtml && !isOauthClientError(err)) {
                            //The error it's not caused by the client and it accepts html.Redirect the client back where all started
                            res.redirect(req.cookies.oauth2_authorization_code_init.start_url);
                            sessionAuthenticate_debug('Client accepts html and occured an error not caused by the client. Redirected to ', req.cookies.oauth2_authorization_code_init.start_url)
                        }
                        else {
                            //If not, let error handler take care of this
                            sessionAuthenticate_debug("Error handler will take care of this");
                            next(err);
                        }
                    })
                    .done();
            }
            else {
                //State received is not the same that was created, probably communication tampering
                //Redirect to authorization url, and retry authentication
                res.redirect(req.cookies.oauth2_authorization_code_init.authorization_url);
                sessionAuthenticate_debug('Query parameters state expected %s, found %s. Client redirected back to authorization url %s', auth_init.state, req.query.state, req.cookies.oauth2_authorization_code_init.authorization_url);
            }
        }
        else {

            if (acceptsHtml) {
                //If client accepts html, we redirect it to the authorization endpoint
                const redirect_url = `${this.oauth_endpoints.authorization}?from_url=${encodeURI(getHref(req))}`;
                res.redirect(redirect_url);
                sessionAuthenticate_debug("The client isn't authenticated and accepts html. Redirect to authorization endpoint with from_url in query parameter\n%s", redirect_url);
            }
            else {
                //Because client doesn't accept html, we launch an UnauthorizedRequestError
                sessionAuthenticate_debug("The client isn't authenticated and does NOT accept html. Throw an OAuthServer.UnauthorizedRequestError");
                //https://tools.ietf.org/html/rfc6750.html#section-3.1
                next(new OAuthServer.UnauthorizedRequestError());
            }
        }
    }
}

OAuthServerMiddleware.prototype.session_authenticate = function () {
    return session_authenticate.bind(this);
}

function oauth2_errorHandler(err, req, res, next) {
    if (isOauthClientError(err)) {
        error_debug("A client error has been thrown\n%O", err);
        res.status(err.code);

        //https://tools.ietf.org/html/rfc6750#section-3.1
        if (err instanceof OAuthServer.UnauthorizedRequestError) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="Service"');
            res.send();
            error_debug('Sent WWW-Authenticate header only. See RFC6750 section 3.1 https://tools.ietf.org/html/rfc6750#section-3.1');
        }
        else {
            //If it's an error derived from a malformed authentication request
            if (!req.originalUrl.startsWith(this.oauth_endpoints.authorization) && !req.originalUrl.startsWith(this.oauth_endpoints.token)) {
                res.setHeader('WWW-Authenticate', utilFormat('Bearer realm="Service",error="%s",error_description="%s"', err.name, err.message))
                error_debug('Set WWW-Authenticate header with error information');
            }

            res.send({
                error: err.name,
                error_description: err.message
            })

            error_debug("Sent error information in body");
        }
    }
    else {
        error_debug("An error has been thrown but it's not a client error, call the next error handler");
        next(err);
    }
}

OAuthServerMiddleware.prototype.errorHandler = function errorHandler() {
    return oauth2_errorHandler.bind(this);
}

function observerMiddleware(callback) {
    return (req, res, next) => {
        callback(req);
        next();
    }
}

function AuthorizationCodeServer(oauthServer_options, options) {

    oauthServer_options = Object.assign(oauthServer_options, {
        userErrorHandler: true,
        debug: oauthServer_options.debug || debug('express-oauth2-server').enabled || debug('oauth2-server').enabled
    });

    const server = new OAuthServerMiddleware(oauthServer_options, options.oauth_endpoints, options.authorizationCode_loginPage_path, options.serverPort);

    var router = Router();

    if (debugConsole.enabled) {
        console.info('OAuth Authorization Code debug info');
        console.group();
        {
            console.group('OAuthServer options (overrided)');
            console.info(oauthServer_options);
            console.groupEnd();
        }

        {
            console.group('AuthorizationCodeServer options')
            console.info(options);
            console.groupEnd();
        }
        console.groupEnd()

        router
            .use((req, res, next) => {
                console.info('OAuth Authorization Code debug info');
                console.group();

                console.group("Express route info");
                console.dir(req.route, { colors: true });
                console.groupEnd();

                console.group('Cookies');
                const cookies = ['oauth2_authorization_code_init', 'oauth2_authorization_code_auth', 'oauth2_token'];
                cookies.forEach(cookieName => { console.log(cookieName); console.dir(req.cookies[cookieName], { colors: true }) });
                console.groupEnd();

                next();
            })
            .use([options.oauth_endpoints.token, options.oauth_endpoints.authorization], observerMiddleware((req) => {
                console.group('Request to oauth endpoint');
                console.info('url: ', req.originalUrl);
                console.info('body: %O', req.body);
                console.groupEnd();
                debugConsole('Request to ', req.originalUrl);
            }))
    }

    router
        .post(options.oauth_endpoints.token, server.token())
        .use(options.oauth_endpoints.authorization, server.authorize());

    if (options.server_description_endpoint) {
        router.get('/oauth_endpoints', (req, res) => {

            const acceptedMediaType = req.accepts(['json', 'application/x-www-form-urlencoded']);
            if (acceptedMediaType) {
                res.status(200);
                res.contentType(acceptedMediaType);

                if (acceptedMediaType === 'json')
                    res.send(options.oauth_endpoints);
                else
                    res.send(qs.stringify(options.oauth_endpoints));

                debugConsole('/oauth_endpoints: response content type ', acceptedMediaType);
            }
            else {
                // https://tools.ietf.org/html/rfc7231#section-6.5.6
                res.setHeader('X-Accepted', "application/json,application/x-www-form-urlencoded;q=0.1");
                res.sendStatus(406);
                debugConsole('/oauth_endpoints: client Accept header ', req.get('Accept'), ', doesn\'t accept json or application/x-www-form-urlencoded, sended 406 (Not Acceptable)');
            }
        });
    }

    router.use(server.errorHandler());

    if (debugConsole.enabled)
        router = router.use(observerMiddleware(() => console.groupEnd()));

    return {
        router: router,
        authenticate_middleware: server.authenticate(),
        session_authenticate_middleware: server.session_authenticate(),
        errorHandler_middleware: server.errorHandler(),
    }
}

exports.AuthorizationCodeServer = AuthorizationCodeServer;