import Koa from 'koa';
import Router from '@koa/router';
import serverless from 'serverless-http';
export interface Route {
    router: Router;
    prefix?: string;
    auth?: boolean;
}
export interface ServerConfig {
    routes: Route[];
    middleware?: Koa.Middleware[];
    cors?: CorsOptions;
    rateLimit?: RateLimitOptions;
    logging?: LoggingOptions;
    metrics?: MetricsOptions;
    auth?: AuthOptions;
}
export interface CorsOptions {
    origins?: string[];
    methods?: string[];
    headers?: string[];
    credentials?: boolean;
}
export interface RateLimitOptions {
    windowMs: number;
    maxRequests: number;
}
export interface LoggingOptions {
    level: 'debug' | 'info' | 'warn' | 'error';
    format?: 'json' | 'text';
    excludePaths?: string[];
}
export interface MetricsOptions {
    namespace: string;
    dimensions?: Record<string, string>;
    enabled: boolean;
}
export interface AuthOptions {
    jwtSecret?: string;
    cognitoUserPoolId?: string;
    cognitoClientId?: string;
    customAuthFn?: (token: string) => Promise<boolean>;
}
export interface RequestUser {
    id: string;
    roles?: string[];
    [key: string]: any;
}
declare module 'koa' {
    interface DefaultState {
        user?: RequestUser;
    }
}
export declare class LambdaServer {
    private app;
    private mainRouter;
    private cloudWatch?;
    private config?;
    constructor();
    private setupCors;
    private setupRateLimit;
    private setupLogging;
    private setupMetrics;
    private setupAuth;
    private recordMetric;
    private verifyJwt;
    private verifyCognito;
    validateBody(schema: any, ctx: Koa.Context): Promise<boolean>;
    createError(status: number, message: string): Error & {
        status: number;
    };
    init(config: ServerConfig): void;
    getHandler(): serverless.Handler;
}
export declare const createLambdaServer: () => LambdaServer;
