"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createLambdaServer = exports.LambdaServer = void 0;
const koa_1 = __importDefault(require("koa"));
const router_1 = __importDefault(require("@koa/router"));
const koa_bodyparser_1 = __importDefault(require("koa-bodyparser"));
const serverless_http_1 = __importDefault(require("serverless-http"));
const aws_sdk_1 = require("aws-sdk");
const koa_pino_logger_1 = __importDefault(require("koa-pino-logger"));
class LambdaServer {
    constructor() {
        this.app = new koa_1.default();
        this.mainRouter = new router_1.default();
    }
    setupCors(options) {
        this.app.use(async (ctx, next) => {
            const origin = ctx.get('Origin');
            if (options.origins?.includes(origin)) {
                ctx.set('Access-Control-Allow-Origin', origin);
                ctx.set('Access-Control-Allow-Methods', options.methods?.join(',') || 'GET,HEAD,PUT,POST,DELETE,PATCH');
                ctx.set('Access-Control-Allow-Headers', options.headers?.join(',') || 'Content-Type,Authorization');
                if (options.credentials) {
                    ctx.set('Access-Control-Allow-Credentials', 'true');
                }
            }
            await next();
        });
    }
    setupRateLimit(options) {
        const requests = new Map();
        this.app.use(async (ctx, next) => {
            const now = Date.now();
            const ip = ctx.ip;
            const userRequests = requests.get(ip) || [];
            const recentRequests = userRequests.filter(time => time > now - options.windowMs);
            if (recentRequests.length >= options.maxRequests) {
                ctx.status = 429;
                ctx.body = { error: 'Too many requests' };
                return;
            }
            recentRequests.push(now);
            requests.set(ip, recentRequests);
            await next();
        });
    }
    setupLogging(options) {
        this.app.use(async (ctx, next) => {
            const start = Date.now();
            try {
                await next();
                if (!options.excludePaths?.includes(ctx.path)) {
                    const ms = Date.now() - start;
                    const log = {
                        level: options.level,
                        method: ctx.method,
                        path: ctx.path,
                        status: ctx.status,
                        duration: ms,
                        timestamp: new Date().toISOString()
                    };
                    if (options.format === 'json') {
                        console.log(JSON.stringify(log));
                    }
                    else {
                        console.log(`${log.timestamp} [${log.level}] ${log.method} ${log.path} ${log.status} ${log.duration}ms`);
                    }
                }
            }
            catch (error) {
                const log = {
                    level: 'error',
                    error: error.message,
                    stack: error.stack,
                    timestamp: new Date().toISOString()
                };
                console.error(options.format === 'json' ? JSON.stringify(log) : `${log.timestamp} [ERROR] ${log.error}`);
                throw error;
            }
        });
    }
    setupMetrics(options) {
        if (options.enabled) {
            this.cloudWatch = new aws_sdk_1.CloudWatch();
            this.app.use(async (ctx, next) => {
                const start = Date.now();
                try {
                    await next();
                    await this.recordMetric('RequestDuration', Date.now() - start, 'Milliseconds', options);
                    await this.recordMetric('RequestCount', 1, 'Count', options);
                }
                catch (error) {
                    await this.recordMetric('ErrorCount', 1, 'Count', options);
                    throw error;
                }
            });
        }
    }
    setupAuth(options) {
        this.app.use(async (ctx, next) => {
            const path = ctx.path;
            const route = this.config?.routes.find(r => path.startsWith(r.prefix || ''));
            if (route?.auth) {
                const token = ctx.headers.authorization?.split(' ')[1];
                if (!token) {
                    ctx.status = 401;
                    ctx.body = { error: 'Unauthorized' };
                    return;
                }
                try {
                    let isAuthenticated = false;
                    if (options.customAuthFn) {
                        isAuthenticated = await options.customAuthFn(token);
                    }
                    else if (options.jwtSecret) {
                        // Implement JWT verification
                        isAuthenticated = await this.verifyJwt(token, options.jwtSecret);
                    }
                    else if (options.cognitoUserPoolId) {
                        // Implement Cognito verification
                        isAuthenticated = await this.verifyCognito(token, options);
                    }
                    if (!isAuthenticated) {
                        ctx.status = 401;
                        ctx.body = { error: 'Invalid token' };
                        return;
                    }
                }
                catch (error) {
                    ctx.status = 401;
                    ctx.body = { error: 'Authentication failed' };
                    return;
                }
            }
            await next();
        });
    }
    // Utility methods
    async recordMetric(name, value, unit, options) {
        if (this.cloudWatch) {
            await this.cloudWatch.putMetricData({
                MetricData: [{
                        MetricName: name,
                        Value: value,
                        Unit: unit,
                        Dimensions: Object.entries(options.dimensions || {}).map(([Name, Value]) => ({ Name, Value }))
                    }],
                Namespace: options.namespace
            }).promise();
        }
    }
    async verifyJwt(token, secret) {
        // Implement JWT verification
        // This is a placeholder - implement actual JWT verification
        return true;
    }
    async verifyCognito(token, options) {
        // Implement Cognito verification
        // This is a placeholder - implement actual Cognito verification
        return true;
    }
    // Public utility methods
    async validateBody(schema, ctx) {
        try {
            // Add your validation logic here
            return true;
        }
        catch (error) {
            ctx.status = 400;
            ctx.body = { error: 'Invalid request body' };
            return false;
        }
    }
    createError(status, message) {
        const error = new Error(message);
        error.status = status;
        return error;
    }
    // Server initialization
    init(config) {
        this.config = config;
        // Setup middleware
        this.app.use((0, koa_bodyparser_1.default)());
        // setup logger
        this.app.use((0, koa_pino_logger_1.default)());
        // Setup configured features
        if (config.cors)
            this.setupCors(config.cors);
        if (config.rateLimit)
            this.setupRateLimit(config.rateLimit);
        if (config.logging)
            this.setupLogging(config.logging);
        if (config.metrics)
            this.setupMetrics(config.metrics);
        if (config.auth)
            this.setupAuth(config.auth);
        // Add custom middleware
        config.middleware?.forEach(middleware => {
            this.app.use(middleware);
        });
        // Add health check
        this.mainRouter.get('/health', async (ctx) => {
            ctx.body = {
                status: 'healthy',
                timestamp: new Date().toISOString()
            };
        });
        // Apply routes
        this.app.use(this.mainRouter.routes());
        this.app.use(this.mainRouter.allowedMethods());
        config.routes.forEach(route => {
            if (route.prefix) {
                route.router.prefix(route.prefix);
            }
            this.app.use(route.router.routes());
            this.app.use(route.router.allowedMethods());
        });
    }
    getHandler() {
        return (0, serverless_http_1.default)(this.app);
    }
}
exports.LambdaServer = LambdaServer;
const createLambdaServer = () => new LambdaServer();
exports.createLambdaServer = createLambdaServer;
