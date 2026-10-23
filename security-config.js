/**
 * Shared security configuration for the Maximo MCP server and the demo proxy,
 * so both enforce the same allowlists.
 */

/** Parse a comma-separated env var into an upper/lower-cased Set (empty Set = not configured). */
function parseList(value, toCase = (s) => s.toUpperCase()) {
    return new Set(
        String(value || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
            .map(toCase)
    );
}

function parseBool(value, defaultValue = false) {
    if (value === undefined || value === null || value === '') return defaultValue;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

// Object Structures allowed when MAXIMO_ALLOWED_OBJECT_STRUCTURES is not set: core work/asset data only.
// People, users and security structures (MXPERSON, MXAPIUSER, ...) must be added explicitly.
const DEFAULT_OBJECT_STRUCTURES = 'MXWO,MXASSET,MXSR,MXLOCATION,MXITEM,MXINVENTORY,MXDOMAIN';

function loadSecurityConfig(env = process.env) {
    const maxPageSize = parseInt(env.MAXIMO_MAX_PAGE_SIZE, 10);
    const osSetting = (env.MAXIMO_ALLOWED_OBJECT_STRUCTURES || '').trim();
    return {
        // Write tools (create_record, update_record, run_action) are disabled unless explicitly enabled.
        writesEnabled: parseBool(env.MAXIMO_ENABLE_WRITES, false),
        // Allowlist of Object Structures the server may touch. Unset = DEFAULT_OBJECT_STRUCTURES; "*" = any valid name.
        allowAllObjectStructures: osSetting === '*',
        allowedObjectStructures: parseList(osSetting === '*' ? '' : osSetting || DEFAULT_OBJECT_STRUCTURES),
        // Allowlist of actions run_action may execute. Unset = changeStatus only; empty = no actions.
        allowedActions: parseList(
            env.MAXIMO_ALLOWED_ACTIONS === undefined ? 'changeStatus' : env.MAXIMO_ALLOWED_ACTIONS,
            (s) => s.toLowerCase()
        ),
        // Related-object queries (rel.xxx, nested {…} selects) can reach data outside the allowlist.
        allowRelatedQueries: parseBool(env.MAXIMO_ALLOW_RELATED_QUERIES, false),
        maxPageSize: Number.isFinite(maxPageSize) && maxPageSize > 0 ? maxPageSize : 100,
    };
}

// Object Structure names are alphanumeric/underscore only. This prevents path traversal
// (e.g. "../../oslc/...") and query-string injection into the request URL.
const OBJECT_STRUCTURE_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/**
 * Validate an Object Structure name and return it upper-cased.
 * Throws if the name is malformed or not on the configured allowlist.
 */
function validateObjectStructure(objectStructure, security) {
    if (typeof objectStructure !== 'string' || !OBJECT_STRUCTURE_PATTERN.test(objectStructure)) {
        throw new Error(
            'Invalid objectStructure: must be an Object Structure name containing only letters, digits and underscores (e.g. MXWO).'
        );
    }
    const osName = objectStructure.toUpperCase();
    if (!security.allowAllObjectStructures && !security.allowedObjectStructures.has(osName)) {
        throw new Error(
            `Object Structure ${osName} is not allowed. Permitted: ${[...security.allowedObjectStructures].join(', ')} (MAXIMO_ALLOWED_OBJECT_STRUCTURES).`
        );
    }
    return osName;
}

function isObjectStructureAllowed(name, security) {
    return security.allowAllObjectStructures || security.allowedObjectStructures.has(String(name).toUpperCase());
}

/**
 * Block OSLC clauses that reach related objects (rel.<relationship> or nested {…} selects),
 * which would bypass the Object Structure allowlist, unless MAXIMO_ALLOW_RELATED_QUERIES=true.
 */
function validateQueryClauses({ where, select, orderBy }, security) {
    if (security.allowRelatedQueries) return;
    for (const [name, value] of Object.entries({ where, select, orderBy })) {
        if (typeof value === 'string' && (/(^|[^A-Za-z0-9_])rel\./i.test(value) || /[{}]/.test(value))) {
            throw new Error(
                `${name} references related objects (rel.… or {…}), which is disabled. Query the related Object Structure directly, or set MAXIMO_ALLOW_RELATED_QUERIES=true.`
            );
        }
    }
}

module.exports = {
    DEFAULT_OBJECT_STRUCTURES,
    OBJECT_STRUCTURE_PATTERN,
    parseList,
    parseBool,
    loadSecurityConfig,
    validateObjectStructure,
    isObjectStructureAllowed,
    validateQueryClauses,
};
