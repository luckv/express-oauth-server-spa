
import { ServerOptions as OAuth2Options } from 'oauth2-server';

import { Router, RequestHandler, ErrorRequestHandler } from 'express-serve-static-core';

interface Options{
    serverPort: number,
    oauth_endpoints : { token: string, authorization: string},
    authorizationCode_loginPage_path: string,
    server_description_endpoint?: boolean 
}

interface Server{
    router: Router,
    authenticate_middleware: RequestHandler,
    session_authenticate_middleware: RequestHandler,
    errorHandler_middleware: ErrorRequestHandler
}

export function AuthorizationCodeServer(server: OAuth2Options, options: Options): Server