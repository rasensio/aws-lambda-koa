import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import serverless from 'serverless-http';
import { CloudWatch } from 'aws-sdk';
import logger  from 'koa-pino-logger';

// Types and Interfaces
export interface Route {
  router: Router;
  prefix?: string;
  auth?: boolean; // Whether this route requires authentication
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

// Utility Types
export interface RequestUser {
  id: string;
  roles?: string[];
  [key: string]: any;
}

// Extend Koa context to include user
declare module 'koa' {
  interface DefaultState {
    user?: RequestUser;
  }
}

export class LambdaServer {
  private app: Koa;
  private mainRouter: Router;
  private cloudWatch?: CloudWatch;
  private config?: ServerConfig;

  constructor() {
    this.app = new Koa();
    this.mainRouter = new Router();
  }

  private setupCors(options: CorsOptions) {
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

  private setupRateLimit(options: RateLimitOptions) {
    const requests = new Map<string, number[]>();

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

  private setupLogging(options: LoggingOptions) {
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
          } else {
            console.log(`${log.timestamp} [${log.level}] ${log.method} ${log.path} ${log.status} ${log.duration}ms`);
          }
        }
      } catch (error:any) {
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

  private setupMetrics(options: MetricsOptions) {
    if (options.enabled) {
      this.cloudWatch = new CloudWatch();
      this.app.use(async (ctx, next) => {
        const start = Date.now();
        try {
          await next();
          await this.recordMetric('RequestDuration', Date.now() - start, 'Milliseconds', options);
          await this.recordMetric('RequestCount', 1, 'Count', options);
        } catch (error) {
          await this.recordMetric('ErrorCount', 1, 'Count', options);
          throw error;
        }
      });
    }
  }

  private setupAuth(options: AuthOptions) {
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
          } else if (options.jwtSecret) {
            // Implement JWT verification
            isAuthenticated = await this.verifyJwt(token, options.jwtSecret);
          } else if (options.cognitoUserPoolId) {
            // Implement Cognito verification
            isAuthenticated = await this.verifyCognito(token, options);
          }

          if (!isAuthenticated) {
            ctx.status = 401;
            ctx.body = { error: 'Invalid token' };
            return;
          }
        } catch (error) {
          ctx.status = 401;
          ctx.body = { error: 'Authentication failed' };
          return;
        }
      }

      await next();
    });
  }

  // Utility methods
  private async recordMetric(
    name: string,
    value: number,
    unit: string,
    options: MetricsOptions
  ) {
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

  private async verifyJwt(token: string, secret: string): Promise<boolean> {
    // Implement JWT verification
    // This is a placeholder - implement actual JWT verification
    return true;
  }

  private async verifyCognito(token: string, options: AuthOptions): Promise<boolean> {
    // Implement Cognito verification
    // This is a placeholder - implement actual Cognito verification
    return true;
  }

  // Public utility methods
  public async validateBody(schema: any, ctx: Koa.Context): Promise<boolean> {
    try {
      // Add your validation logic here
      return true;
    } catch (error) {
      ctx.status = 400;
      ctx.body = { error: 'Invalid request body' };
      return false;
    }
  }

  public createError(status: number, message: string): Error & { status: number } {
    const error = new Error(message) as Error & { status: number };
    error.status = status;
    return error;
  }

  // Server initialization
  public init(config: ServerConfig) {
    this.config = config;

    // Setup middleware
    this.app.use(bodyParser());
    // setup logger
    this.app.use(logger());

    // Setup configured features
    if (config.cors) this.setupCors(config.cors);
    if (config.rateLimit) this.setupRateLimit(config.rateLimit);
    if (config.logging) this.setupLogging(config.logging);
    if (config.metrics) this.setupMetrics(config.metrics);
    if (config.auth) this.setupAuth(config.auth);


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

  public getHandler() {
    return serverless(this.app);
  }
}

export const createLambdaServer = () => new LambdaServer();
