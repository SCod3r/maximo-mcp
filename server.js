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
 *  - Binds to 127.0.0.1 by default, so it is not reachable from the network.
 *  - Rejects requests whose Host header is not localhost (blocks DNS-rebinding attacks).
 *  - Rejects cross-site browser requests (no permissive CORS), so other websites you visit
 *    cannot use the proxy — and the API key it injects — on your behalf.
 *  - Only proxies Object Structure reads (GET) unless MAXIMO_ENABLE_WRITES=true.
 *  - Verifies Maximo's TLS certificate unless MAXIMO_PROXY_INSECURE_TLS=true.
 *  - Serves only the demos/, images/ and docs/ folders — never the project root.
 */
require('dotenv').config({ quiet: true, path: require('path').join(__dirname, '.env') });

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const PORT = parseInt(process.env.PORT, 10) || 3002;
const HOST = process.env.HOST || '127.0.0.1';
const API_TARGET = process.env.MAXIMO_HOST || 'https://your-maximo-host.com';
const API_KEY = process.env.MAXIMO_API_KEY;
const WRITES_ENABLED = /^(1|true|yes|on)$/i.test(process.env.MAXIMO_ENABLE_WRITES || '');
const INSECURE_TLS = /^(1|true|yes|on)$/i.test(process.env.MAXIMO_PROXY_INSECURE_TLS || '');

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

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

/** Only allow Object Structure API calls; only GET unless writes are enabled. */
function restrictApiSurface(req, res, next) {
    const pathname = req.path || '';
    if (!/^\/maximo\/api\/os(\/|$)/i.test(pathname) || /\.\.|%2e|%2f|%5c/i.test(pathname)) {
        return res.status(403).send('Forbidden: only /maximo/api/os/* is proxied.');
    }
    if (req.method !== 'GET' && !WRITES_ENABLED) {
        return res.status(403).send('Forbidden: write requests are disabled (set MAXIMO_ENABLE_WRITES=true).');
    }
    next();
}

function createApp() {
    const app = express();
    app.disable('x-powered-by');

    app.use(requireLocalHost);

    // Log method and path only (query strings can contain record data).
    app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
        next();
    });

    app.use(
        '/maximo',
        requireSameOrigin,
        (req, res, next) => {
            // Express strips the mount path; check against the full original path.
            req.fullPath = req.baseUrl + req.path;
            restrictApiSurface({ path: req.fullPath, method: req.method }, res, next);
        },
        createProxyMiddleware({
            target: API_TARGET,
            changeOrigin: true,
            secure: !INSECURE_TLS,
            // Express removed "/maximo" from req.url — put it back for the upstream request.
            pathRewrite: (p) => `/maximo${p}`,
            on: {
                proxyReq: (proxyReq) => {
                    // Never forward browser cookies or credentials; use the server-side API key.
                    proxyReq.removeHeader('cookie');
                    proxyReq.removeHeader('authorization');
                    proxyReq.removeHeader('maxauth');
                    if (API_KEY) proxyReq.setHeader('apikey', API_KEY);
                    else proxyReq.removeHeader('apikey');
                },
                proxyRes: (proxyRes) => {
                    delete proxyRes.headers['access-control-allow-origin'];
                    delete proxyRes.headers['set-cookie'];
                },
            },
        })
    );

    // Serve only the demo assets — never the project root (which may hold config files).
    app.get('/', (req, res) => res.redirect('/demos/index.html'));
    app.use('/demos', express.static(path.join(__dirname, 'demos')));
    app.use('/images', express.static(path.join(__dirname, 'images')));
    app.use('/docs', express.static(path.join(__dirname, 'docs')));

    return app;
}

if (require.main === module) {
    if (INSECURE_TLS) {
        console.warn('WARNING: TLS certificate verification to Maximo is DISABLED (MAXIMO_PROXY_INSECURE_TLS=true).');
    }
    if (!API_KEY) {
        console.warn('WARNING: MAXIMO_API_KEY is not set; proxied requests will be unauthenticated.');
    }
    createApp().listen(PORT, HOST, () => {
        console.log(`\n==================================================`);
        console.log(`🚀 Maximo App Proxy Server`);
        console.log(`==================================================`);
        console.log(`Server running at: http://localhost:${PORT} (bound to ${HOST})`);
        console.log(`Proxying /maximo/api/os -> ${API_TARGET}/maximo/api/os ${WRITES_ENABLED ? '(read/write)' : '(read-only)'}`);
        console.log(`\nDemo Apps:`);
        console.log(`  • Asset Manager: http://localhost:${PORT}/demos/assets.html`);
        console.log(`  • Work Orders:   http://localhost:${PORT}/demos/index.html`);
        console.log(`  • Carbon Table:  http://localhost:${PORT}/demos/carbon_workorders.html`);
        console.log(`\nPress Ctrl+C to stop.`);
    });
}

module.exports = { createApp, _internal: { hostnameOf, requireLocalHost, requireSameOrigin, restrictApiSurface } };
