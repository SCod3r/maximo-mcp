/**
 * Security tests for the Maximo MCP server and the demo proxy.
 */
const http = require('http');
const request = require('supertest');

const realFetch = global.fetch;

// Silence server logging (installed before describe blocks load modules).
jest.spyOn(console, 'error').mockImplementation(() => {});
jest.spyOn(console, 'warn').mockImplementation(() => {});
jest.spyOn(console, 'log').mockImplementation(() => {});

const BASE_ENV = {
    MAXIMO_URL: 'https://maximo.example.com/maximo/api',
    MAXIMO_API_KEY: 'test-key',
    MAXIMO_OPENAPI_PATH: '/nonexistent/openapi.json',
};

/** Load a fresh copy of the MCP server module with the given environment. */
function loadServer(env = {}) {
    const saved = { ...process.env };
    for (const k of Object.keys(process.env)) if (k.startsWith('MAXIMO_')) delete process.env[k];
    Object.assign(process.env, BASE_ENV, env);
    let mod;
    jest.isolateModules(() => {
        mod = require('./maximo-mcp-server.js');
    });
    process.env = saved;
    return mod._internal;
}

/** Mock global fetch, recording calls and returning the given JSON body. */
function mockFetch(body = { member: [] }, status = 200) {
    const calls = [];
    global.fetch = jest.fn(async (url, opts) => {
        calls.push({ url: String(url), opts });
        return {
            ok: status >= 200 && status < 300,
            status,
            statusText: 'OK',
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => body,
            text: async () => JSON.stringify(body),
        };
    });
    return calls;
}


describe('Object Structure validation (path traversal)', () => {
    const s = loadServer();

    test.each([
        '../../oslc/whoami',
        '../script/FOO',
        'MXPERSON?oslc.select=*&x=',
        'MXWO/123',
        'MXWO#frag',
        '%2e%2e',
        '',
        ' MXWO',
        'A'.repeat(65),
    ])('rejects %p', (os) => {
        expect(() => s.validateObjectStructure(os)).toThrow(/Invalid objectStructure/);
    });

    test('accepts and upper-cases valid names', () => {
        expect(s.validateObjectStructure('mxwo')).toBe('MXWO');
        expect(s.validateObjectStructure('MX_ASSET2')).toBe('MX_ASSET2');
    });

    test('enforces the allowlist when configured', () => {
        const restricted = loadServer({ MAXIMO_ALLOWED_OBJECT_STRUCTURES: 'MXWO, mxasset' });
        expect(restricted.validateObjectStructure('mxasset')).toBe('MXASSET');
        expect(() => restricted.validateObjectStructure('MXPERSON')).toThrow(/not in MAXIMO_ALLOWED_OBJECT_STRUCTURES/);
    });

    test('query_maximo never builds a URL outside /os/{name}', async () => {
        const calls = mockFetch();
        await expect(s.queryMaximo({ objectStructure: '../../oslc/whoami' })).rejects.toThrow();
        expect(calls).toHaveLength(0);

        await s.queryMaximo({ objectStructure: 'mxwo', where: 'status="APPR"', formatted: false });
        const url = new URL(calls[0].url);
        expect(url.pathname).toBe('/maximo/api/os/MXWO');
        expect(url.searchParams.get('oslc.where')).toBe('status="APPR"');
    });

    test('render tools validate the Object Structure too', async () => {
        const calls = mockFetch();
        await expect(s.renderCarbonTable({ objectStructure: '../x' })).rejects.toThrow();
        await expect(s.renderCarbonDetails({ objectStructure: '../x', where: 'a=1' })).rejects.toThrow();
        expect(calls).toHaveLength(0);
    });
});

describe('pageSize clamping', () => {
    test('clamps to MAXIMO_MAX_PAGE_SIZE and defaults bad values', () => {
        const s = loadServer({ MAXIMO_MAX_PAGE_SIZE: '50' });
        expect(s.clampPageSize(100000)).toBe(50);
        expect(s.clampPageSize(5)).toBe(5);
        expect(s.clampPageSize(-1)).toBe(10);
        expect(s.clampPageSize('abc')).toBe(10);
    });
});

describe('Write tools are read-only by default', () => {
    test('write tools are hidden and refused when writes are disabled', async () => {
        const s = loadServer();
        const names = s.getToolDefinitions().map((t) => t.name);
        expect(names).not.toEqual(expect.arrayContaining(['create_record']));
        expect(names).not.toContain('update_record');
        expect(names).not.toContain('run_action');

        const calls = mockFetch();
        for (const fn of [s.createRecord, s.updateRecord, s.runAction]) {
            const res = await fn({ objectStructure: 'MXWO', recordId: 'X', recordData: {}, action: 'changeStatus' });
            expect(res.isError).toBe(true);
            expect(res.content[0].text).toMatch(/read-only mode/);
        }
        expect(calls).toHaveLength(0);
    });

    test('write tools are listed with annotations when enabled', () => {
        const s = loadServer({ MAXIMO_ENABLE_WRITES: 'true' });
        const tools = Object.fromEntries(s.getToolDefinitions().map((t) => [t.name, t]));
        expect(tools.update_record.annotations.destructiveHint).toBe(true);
        expect(tools.run_action.annotations.readOnlyHint).toBe(false);
        expect(tools.query_maximo.annotations.readOnlyHint).toBe(true);
    });

    test('run_action only runs allowlisted actions', async () => {
        const s = loadServer({ MAXIMO_ENABLE_WRITES: 'true' });
        const calls = mockFetch({});
        await expect(
            s.runAction({ objectStructure: 'MXWO', recordId: '_QkVERk9SRC8xMDAx', action: 'wsmethod:approve' })
        ).rejects.toThrow(/not allowed/);
        expect(calls).toHaveLength(0);

        await s.runAction({
            objectStructure: 'MXWO',
            recordId: '_QkVERk9SRC8xMDAx',
            action: 'changeStatus',
            actionData: { status: 'APPR' },
        });
        expect(calls).toHaveLength(1);
        expect(new URL(calls[0].url).pathname).toBe('/maximo/api/os/MXWO/_QkVERk9SRC8xMDAx');
    });

    test('custom action allowlist', () => {
        const s = loadServer({ MAXIMO_ALLOWED_ACTIONS: 'changeStatus,wsmethod:approve' });
        expect(s.validateAction('WSMETHOD:APPROVE')).toBe('WSMETHOD:APPROVE');
    });

    test('recordId cannot traverse paths', async () => {
        const s = loadServer({ MAXIMO_ENABLE_WRITES: 'true' });
        mockFetch({});
        for (const id of ['..', '.', 'a/b', 'a?b', 'a b', '']) {
            await expect(s.updateRecord({ objectStructure: 'MXWO', recordId: id, recordData: {} })).rejects.toThrow();
        }
    });

    test('recordData must be a JSON object', async () => {
        const s = loadServer({ MAXIMO_ENABLE_WRITES: 'true' });
        mockFetch({});
        await expect(s.createRecord({ objectStructure: 'MXWO', recordData: '[1,2]' })).rejects.toThrow(/JSON object/);
        await expect(s.createRecord({ objectStructure: 'MXWO', recordData: '{bad' })).rejects.toThrow(/valid JSON/);
    });
});

describe('HTML escaping in render tools (XSS)', () => {
    const payload = '<img src=x onerror=alert(1)>';

    test('escapeHtml escapes all special characters', () => {
        const s = loadServer();
        expect(s.escapeHtml(`<a href="x" onclick='y'>&</a>`)).toBe(
            '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;'
        );
    });

    test('render_carbon_table escapes record values, keys and title', async () => {
        const s = loadServer();
        mockFetch({ member: [{ wonum: '1001', description: payload, [payload]: 'k' }], responseInfo: { totalCount: 1 } });
        const res = await s.renderCarbonTable({ objectStructure: 'MXWO', title: payload });
        const html = res.content[0].text;
        expect(html).not.toContain(payload);
        expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
        expect(html).toContain('Content-Security-Policy');
    });

    test('render_carbon_details escapes record values and keys', async () => {
        const s = loadServer();
        mockFetch({ member: [{ wonum: '1001', description: payload, [payload]: 'k' }] });
        const res = await s.renderCarbonDetails({ objectStructure: 'MXWO', where: 'wonum="1001"' });
        expect(res.content[0].text).not.toContain(payload);
    });

    test('query_maximo returns JSON (not HTML) by default, with an untrusted-data notice', async () => {
        const s = loadServer();
        mockFetch({ member: [{ wonum: '1001' }] });
        const res = await s.queryMaximo({ objectStructure: 'MXWO' });
        const parsed = JSON.parse(res.content[0].text);
        expect(parsed.records).toHaveLength(1);
        expect(parsed.notice).toMatch(/untrusted/i);
    });
});

describe('Transport safety (maximoFetch)', () => {
    let mx;
    let idp;
    let hang;
    let seen;
    let urls;

    beforeAll(async () => {
        global.fetch = realFetch;
        seen = [];
        idp = http.createServer((req, res) => {
            seen.push({ host: 'idp', apikey: req.headers.apikey });
            res.setHeader('content-type', 'text/html');
            res.end('<html>Sign in</html>');
        });
        hang = http.createServer(() => {});
        await new Promise((r) => idp.listen(0, '127.0.0.1', r));
        await new Promise((r) => hang.listen(0, '127.0.0.1', r));
        mx = http.createServer((req, res) => {
            seen.push({ host: 'maximo', apikey: req.headers.apikey, url: req.url });
            if (req.url.includes('/os/MXREDIRECT')) {
                res.statusCode = 302;
                res.setHeader('location', `http://localhost:${idp.address().port}/authorize`);
                return res.end();
            }
            if (req.url.includes('/os/MXLOGIN')) {
                res.setHeader('content-type', 'text/html; charset=utf-8');
                return res.end('<html>Sign in</html>');
            }
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ member: [{ wonum: '1', description: 'x'.repeat(5000) }] }));
        });
        await new Promise((r) => mx.listen(0, '127.0.0.1', r));
        urls = {
            mx: `http://127.0.0.1:${mx.address().port}/maximo/api`,
            hang: `http://127.0.0.1:${hang.address().port}/maximo/api`,
        };
    });

    afterAll(async () => {
        global.fetch = realFetch;
        await Promise.all([mx, idp, hang].map((srv) => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); })));
    });

    beforeEach(() => {
        global.fetch = realFetch;
        seen.length = 0;
    });

    test('does not follow redirects, so the API key never reaches the SSO host', async () => {
        const s = loadServer({ MAXIMO_URL: urls.mx });
        const res = await s.queryMaximo({ objectStructure: 'MXREDIRECT' });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toMatch(/redirect/);
        expect(seen.filter((r) => r.host === 'idp')).toHaveLength(0);
    });

    test('reports an HTML login page clearly instead of a JSON parse error', async () => {
        const s = loadServer({ MAXIMO_URL: urls.mx });
        const res = await s.queryMaximo({ objectStructure: 'MXLOGIN' });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toMatch(/HTML page/);
    });

    test('times out instead of hanging', async () => {
        const s = loadServer({ MAXIMO_URL: urls.hang, MAXIMO_TIMEOUT_MS: '300' });
        const started = Date.now();
        const res = await s.queryMaximo({ objectStructure: 'MXWO' });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toMatch(/did not respond/);
        expect(Date.now() - started).toBeLessThan(5000);
    });

    test('refuses plain http to a non-local host', async () => {
        const s = loadServer({ MAXIMO_URL: 'http://maximo.example.com/maximo/api' });
        const res = await s.queryMaximo({ objectStructure: 'MXWO' });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toMatch(/unencrypted/);
        expect(s.resolveMaximoOrigin('http://maximo.example.com/maximo', { MAXIMO_ALLOW_INSECURE_HTTP: 'true' }).error).toBeNull();
    });

    test('never sends the API key to another origin', async () => {
        const s = loadServer({ MAXIMO_URL: urls.mx });
        await expect(s.maximoFetch('https://evil.example.com/maximo/api/os/MXWO', {})).rejects.toThrow(/other than MAXIMO_URL/);
    });

    test('caps oversized tool output', () => {
        const s = loadServer({ MAXIMO_MAX_OUTPUT_CHARS: '1000' });
        const out = s.capToolOutput({ content: [{ type: 'text', text: 'y'.repeat(5000) }] });
        expect(out.content[0].text.length).toBeLessThan(1300);
        expect(out.content[0].text).toMatch(/truncated/);
    });
});

describe('Demo proxy (server.js)', () => {
    let upstream;
    let upstreamRequests;
    let app;

    beforeAll(async () => {
        upstreamRequests = [];
        upstream = http.createServer((req, res) => {
            upstreamRequests.push({ url: req.url, headers: req.headers, method: req.method });
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Set-Cookie', 'JSESSIONID=abc');
            res.end(JSON.stringify({ member: [] }));
        });
        await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
        const saved = { ...process.env };
        process.env.MAXIMO_HOST = `http://127.0.0.1:${upstream.address().port}`;
        process.env.MAXIMO_API_KEY = 'server-side-key';
        delete process.env.MAXIMO_ENABLE_WRITES;
        jest.isolateModules(() => {
            app = require('./server.js').createApp();
        });
        process.env = saved;
    });

    afterAll(() => new Promise((r) => upstream.close(r)));
    beforeEach(() => (upstreamRequests.length = 0));

    const local = (req) => req.set('Host', 'localhost:3002');

    test('proxies same-origin GETs to /maximo/api/os and injects the API key', async () => {
        const res = await local(request(app).get('/maximo/api/os/mxwo?lean=1')).set('Cookie', 'x=y');
        expect(res.status).toBe(200);
        expect(upstreamRequests).toHaveLength(1);
        expect(upstreamRequests[0].url).toBe('/maximo/api/os/mxwo?lean=1');
        expect(upstreamRequests[0].headers.apikey).toBe('server-side-key');
        expect(upstreamRequests[0].headers.cookie).toBeUndefined();
        expect(res.headers['access-control-allow-origin']).toBeUndefined();
        expect(res.headers['set-cookie']).toBeUndefined();
    });

    test('rejects non-localhost Host headers (DNS rebinding)', async () => {
        const res = await request(app).get('/maximo/api/os/mxwo').set('Host', 'evil.example.com');
        expect(res.status).toBe(403);
        expect(upstreamRequests).toHaveLength(0);
    });

    test('rejects cross-site requests', async () => {
        let res = await local(request(app).get('/maximo/api/os/mxwo')).set('Origin', 'https://evil.example.com');
        expect(res.status).toBe(403);
        res = await local(request(app).get('/maximo/api/os/mxwo')).set('Sec-Fetch-Site', 'cross-site');
        expect(res.status).toBe(403);
        expect(upstreamRequests).toHaveLength(0);
    });

    test('only proxies Object Structure paths', async () => {
        for (const p of ['/maximo/oslc/whoami', '/maximo/api/script/FOO', '/maximo/api/os/../script/FOO', '/maximo/api/os/%2e%2e/script']) {
            const res = await local(request(app).get(p));
            expect(res.status).toBe(403);
        }
        expect(upstreamRequests).toHaveLength(0);
    });

    test('blocks writes unless enabled', async () => {
        const res = await local(request(app).post('/maximo/api/os/mxwo').send({}));
        expect(res.status).toBe(403);
        expect(upstreamRequests).toHaveLength(0);
    });

    test('does not serve files from the project root', async () => {
        for (const p of ['/package.json', '/.env', '/maximo-mcp-server.js', '/server.js']) {
            const res = await local(request(app).get(p));
            expect(res.status).toBe(404);
        }
        const demo = await local(request(app).get('/demos/index.html'));
        expect(demo.status).toBe(200);
    });
});
