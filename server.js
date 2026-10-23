/**
 * Maximo Proxy Server
 *
 * Author: Markus van Kempen
 * Date: 3 Feb 2026
 *
 * Description: A local Express.js proxy for the demo apps. It forwards /maximo/api/os/* requests
 * to the Maximo API (adding the API key from .env server-side) and serves the demo pages.
 *
 * Security model:
 *  - Binds to 127.0.0.1 by default and rejects non-localhost Host headers (DNS rebinding).
 *  - Requires a random per-launch access token. Open the URL printed at startup once; the token is
 *    then kept in an HttpOnly, SameSite=Strict cookie. Other local processes/users and other
 *    websites cannot use the proxy (and the API key it injects) without it.
 *  - Rejects cross-site browser requests; no permissive CORS.
 *  - Only proxies Object Structure calls on the shared allowlist (MAXIMO_ALLOWED_OBJECT_STRUCTURES),
 *    blocks related-object query clauses, and only allows GET unless MAXIMO_ENABLE_WRITES=true.
 *  - Forwards only a short list of request headers (no method overrides, cookies or credentials).
 *  - Verifies Maximo's TLS certificate unless MAXIMO_PROXY_INSECURE_TLS=true.
 *  - Serves only demos/, images/ and docs/, with a Content-Security-Policy that only allows
 *    scripts from this origin (third-party libraries are vendored in demos/vendor/).
 */
const path = require('path');
require('dotenv').config({ quiet: true, path: path.join(__dirname, '.env') });

const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const {
    loadSecurityConfig,
    validateObjectStructure,
    validateQueryClauses,
    parseBool,
} = require('./security-config');

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);
const COOKIE_NAME = 'maximo_proxy_token';
// Request headers passed through to Maximo. Everything else (cookies, authorization,
// x-method-override, properties, …) is dropped; the API key is added server-side.
const FORWARDED_HEADERS = new Set(['accept', 'accept-language', 'content-type', 'content-length', 'host', 'connection']);

const STATIC_CSP = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com",
    "font-src 'self' data: https://fonts.gstatic.com https://unpkg.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'none'",
    "base-uri 'none'",
].join('; ');

function hostnameOf(hostHeader) {
    if (!hostHeader) return '';
    const h = String(hostHeader).toLowerCase();
    if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1);
    return h.split(':')[0];
}

/** Block DNS rebinding: only accept requests addressed to a local hostname. */
function requireLocalHost(req, res, next) {
    if (!LOCAL_HOSTNAMES.has(hostnameOf(req.headers.host))) {
        return res.status(403).send('Forbidden: proxy only accepts requests to localhost.');
    }
    next();
}

/** Reject absolute-form request targets and double-encoded paths before any routing. */
function requireCleanTarget(req, res, next) {
    const target = req.originalUrl || '';
    if (!target.startsWith('/') || target.startsWith('//')) {
        return res.status(400).send('Bad request target.');
    }
    const pathPart = target.split('?')[0];
    if (/%25|%2e|%2f|%5c|\\|\/\.\.?(\/|$)|;/i.test(pathPart)) {
        return res.status(400).send('Bad request path.');
    }
    next();
}

function parseCookies(header) {
    const out = {};
    for (const part of String(header || '').split(';')) {
        const i = part.indexOf('=');
        if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return out;
}

function tokensMatch(a, b) {
    const ba = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));
    return ba.length === bb.length && ba.length > 0 && crypto.timingSafeEqual(ba, bb);
}

/** Per-launch token: accepted once via ?token=, then carried in an HttpOnly SameSite=Strict cookie. */
function requireToken(token) {
    return (req, res, next) => {
        if (req.method === 'GET' && typeof req.query.token === 'string' && tokensMatch(req.query.token, token)) {
            res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/`);
            const clean = new URL(req.originalUrl, 'http://localhost');
            clean.searchParams.delete('token');
            return res.redirect(303, clean.pathname + (clean.search || ''));
        }
        if (tokensMatch(parseCookies(req.headers.cookie)[COOKIE_NAME], token)) return next();
        return res
            .status(401)
            .send('Unauthorized: open the URL with ?token=… printed in the proxy console when it started.');
    };
}

/** Block cross-site use of the proxy (CSRF / data theft by other websites). */
function requireSameOrigin(req, res, next) {
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin' && site !== 'none') {
        return res.status(403).send('Forbidden: cross-site requests are not allowed.');
    }
    const origin = req.headers.origin;
    if (origin) {
        let originHost = '';
        try {
            originHost = new URL(origin).host.toLowerCase();
        } catch {
            return res.status(403).send('Forbidden: invalid Origin.');
        }
        if (originHost !== String(req.headers.host || '').toLowerCase()) {
            return res.status(403).send('Forbidden: cross-origin requests are not allowed.');
        }
    }
    next();
}

/** Only allow allowlisted Object Structure calls; only GET unless writes are enabled. */
function restrictApiSurface(security) {
    return (req, res, next) => {
        const fullPath = req.baseUrl + req.path;
        const m = /^\/maximo\/api\/os\/([^/]+)(\/[^/]+)?\/?$/i.exec(fullPath);
        if (!m) return res.status(403).send('Forbidden: only /maximo/api/os/{ObjectStructure} is proxied.');
        try {
            validateObjectStructure(m[1], security);
            const q = req.query || {};
            const clause = (v) => (Array.isArray(v) ? v.join(',') : v);
            validateQueryClauses(
                { where: clause(q['oslc.where']), select: clause(q['oslc.select']), orderBy: clause(q['oslc.orderBy']) },
                security
            );
        } catch (e) {
            return res.status(403).send(`Forbidden: ${e.message}`);
        }
        if (req.method !== 'GET' && !security.writesEnabled) {
            return res.status(403).send('Forbidden: write requests are disabled (set MAXIMO_ENABLE_WRITES=true).');
        }
        if (req.method !== 'GET' && req.method !== 'POST') {
            return res.status(405).send('Method not allowed.');
        }
        next();
    };
}

function staticHeaders(res) {
    res.setHeader('Content-Security-Policy', STATIC_CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
}

function createApp(options = {}) {
    const env = options.env || process.env;
    const security = loadSecurityConfig(env);
    const token = options.token || crypto.randomBytes(24).toString('base64url');
    const apiTarget = env.MAXIMO_HOST || 'https://your-maximo-host.com';
    const apiKey = env.MAXIMO_API_KEY;
    const insecureTls = parseBool(env.MAXIMO_PROXY_INSECURE_TLS, false);

    const app = express();
    app.disable('x-powered-by');
    app.locals.token = token;
    app.locals.security = security;

    app.use(requireLocalHost);
    app.use(requireCleanTarget);

    // Log method and path only (query strings can contain record data or the token).
    app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
        next();
    });

    app.use(requireToken(token));

    app.use(
        '/maximo',
        requireSameOrigin,
        restrictApiSurface(security),
        createProxyMiddleware({
            target: apiTarget,
            changeOrigin: true,
            secure: !insecureTls,
            // Express removed "/maximo" from req.url — put it back for the upstream request.
            pathRewrite: (p) => `/maximo${p}`,
            on: {
                proxyReq: (proxyReq) => {
                    for (const name of proxyReq.getHeaderNames()) {
                        if (!FORWARDED_HEADERS.has(name.toLowerCase())) proxyReq.removeHeader(name);
                    }
                    if (apiKey) proxyReq.setHeader('apikey', apiKey);
                },
                proxyRes: (proxyRes) => {
                    delete proxyRes.headers['access-control-allow-origin'];
                    delete proxyRes.headers['set-cookie'];
                    // Do not hand Maximo/SSO redirects to the browser as navigations.
                    if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
                        delete proxyRes.headers.location;
                        proxyRes.statusCode = 502;
                    }
                },
            },
        })
    );

    // Serve only the demo assets — never the project root (which may hold config files).
    const staticOpts = { setHeaders: staticHeaders, dotfiles: 'ignore', index: false };
    app.get('/', (req, res) => res.redirect('/demos/index.html'));
    const openapiFile = env.MAXIMO_OPENAPI_PATH || path.join(__dirname, 'maximo_openapi.json');
    app.get('/demos/maximo_openapi.json', (req, res) => {
        if (!fs.existsSync(openapiFile)) return res.status(404).send('maximo_openapi.json not found.');
        staticHeaders(res);
        res.sendFile(path.resolve(openapiFile));
    });
    app.use('/demos', express.static(path.join(__dirname, 'demos'), staticOpts));
    app.use('/images', express.static(path.join(__dirname, 'images'), staticOpts));
    app.use('/docs', express.static(path.join(__dirname, 'docs'), staticOpts));

    return app;
}

if (require.main === module) {
    const PORT = parseInt(process.env.PORT, 10) || 3002;
    const HOST = process.env.HOST || '127.0.0.1';
    if (parseBool(process.env.MAXIMO_PROXY_INSECURE_TLS, false)) {
        console.warn('WARNING: TLS certificate verification to Maximo is DISABLED (MAXIMO_PROXY_INSECURE_TLS=true).');
    }
    if (!process.env.MAXIMO_API_KEY) {
        console.warn('WARNING: MAXIMO_API_KEY is not set; proxied requests will be unauthenticated.');
    }
    const app = createApp();
    const { token, security } = app.locals;
    app.listen(PORT, HOST, () => {
        const base = `http://localhost:${PORT}`;
        console.log(`\n==================================================`);
        console.log(`🚀 Maximo App Proxy Server`);
        console.log(`==================================================`);
        console.log(`Bound to ${HOST}:${PORT}. Proxying allowlisted /maximo/api/os/* ${security.writesEnabled ? '(read/write)' : '(read-only)'}`);
        console.log(`\nOpen once to authorize this browser (keep this token private):`);
        console.log(`  ${base}/demos/index.html?token=${token}`);
        console.log(`\nDemo Apps (after authorizing):`);
        console.log(`  • Asset Manager: ${base}/demos/assets.html`);
        console.log(`  • Work Orders:   ${base}/demos/index.html`);
        console.log(`  • Carbon Table:  ${base}/demos/carbon_workorders.html`);
        console.log(`\nPress Ctrl+C to stop.`);
    });
}

module.exports = {
    createApp,
    _internal: { hostnameOf, requireLocalHost, requireCleanTarget, requireSameOrigin, restrictApiSurface, requireToken },
};
