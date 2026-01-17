const http = require('http');
const { randomUUID } = require('crypto');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const Busboy = require('busboy');
const querystring = require('querystring');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { GoogleGenerativeAI } = require('@google/generative-ai');
const { SchemaType } = require('@google/generative-ai');

const BODY_LIMIT_BYTES = 20 * 1024 * 1024;
const SESSION_COOKIE_NAME = 'fc_session';
const SESSION_TTL = 24 * 60 * 60 * 1000;
const STATIC_METHODS = ['GET', 'HEAD'];
const ALLOWED_ORIGIN_PREFIXES = ['http://localhost:'];
const ALLOWED_HEADERS = 'Content-Type, Authorization, X-Requested-With';
const ALLOWED_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8'
};

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return MIME_TYPES[ext] || 'application/octet-stream';
}

function parseCookies(header = '') {
    return header.split(';').reduce((acc, part) => {
        const [key, ...rest] = part.trim().split('=');
        if (!key) return acc;
        acc[key] = decodeURIComponent(rest.join('=').trim());
        return acc;
    }, {});
}

function isOriginAllowed(origin) {
    if (!origin) return true;
    return ALLOWED_ORIGIN_PREFIXES.some(prefix => origin.startsWith(prefix));
}

function applyCorsHeaders(req, res) {
    const origin = req.headers.origin;

    if (origin) {
        if (!isOriginAllowed(origin)) {
            return false;
        }
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    }

    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS);
    res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS);
    res.setHeader('Access-Control-Expose-Headers', 'set-cookie');

    return true;
}

function readRequestBody(stream, limitBytes) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;

        stream.on('data', chunk => {
            total += chunk.length;
            if (total > limitBytes) {
                stream.pause();
                reject(new Error('Payload too large'));
                return;
            }
            chunks.push(chunk);
        });

        stream.on('end', () => {
            resolve(Buffer.concat(chunks));
        });

        stream.on('error', reject);
    });
}

class ResponseWrapper {
    constructor(res, options = {}) {
        this.raw = res;
        this.statusCode = 200;
        this.ended = false;
        this.beforeSend = options.beforeSend || null;
    }

    _ensureBeforeSend() {
        if (this.beforeSend) {
            this.beforeSend();
            this.beforeSend = null;
        }
    }

    setHeader(name, value) {
        if (this.ended) return;
        this.raw.setHeader(name, value);
    }

    appendHeader(name, value) {
        if (this.ended) return;
        const current = this.raw.getHeader(name);
        if (!current) {
            this.raw.setHeader(name, value);
        } else if (Array.isArray(current)) {
            this.raw.setHeader(name, current.concat(value));
        } else {
            this.raw.setHeader(name, [current, value]);
        }
    }

    status(code) {
        this.statusCode = code;
        return this;
    }

    send(payload = '') {
        if (this.ended) return;
        this._ensureBeforeSend();
        if (Buffer.isBuffer(payload)) {
            this.raw.setHeader('Content-Type', 'application/octet-stream');
            this.raw.statusCode = this.statusCode;
            this.raw.end(payload);
        } else if (typeof payload === 'object') {
            this.json(payload);
            return;
        } else {
            this.raw.setHeader('Content-Type', 'text/plain; charset=utf-8');
            this.raw.statusCode = this.statusCode;
            this.raw.end(String(payload));
        }
        this.ended = true;
    }

    json(data) {
        if (this.ended) return;
        this._ensureBeforeSend();
        this.raw.setHeader('Content-Type', 'application/json');
        this.raw.statusCode = this.statusCode;
        this.raw.end(JSON.stringify(data));
        this.ended = true;
    }

    sendFile(filePath) {
        if (this.ended) return;
        const resolved = path.resolve(filePath);

        fs.stat(resolved, (err, stats) => {
            if (err || !stats.isFile()) {
                this.status(404).json({ error: 'File not found' });
                return;
            }

            this._ensureBeforeSend();
            this.raw.statusCode = this.statusCode;
            this.raw.setHeader('Content-Type', getMimeType(resolved));

            const stream = fs.createReadStream(resolved);
            stream.on('error', () => {
                if (!this.ended) {
                    this.status(500).json({ error: 'Failed to read file' });
                }
            });
            stream.pipe(this.raw);
            this.ended = true;
        });
    }

    clearCookie(name) {
        this.appendHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
    }
}

class SessionManager {
    constructor({ cookieName, maxAge, sameSite = 'Lax', secure = false } = {}) {
        this.cookieName = cookieName || SESSION_COOKIE_NAME;
        this.maxAge = maxAge || SESSION_TTL;
        this.sameSite = sameSite;
        this.secure = secure;
        this.store = new Map();
    }

    _buildCookie(value) {
        const attributes = [
            `${this.cookieName}=${value}`,
            'Path=/',
            `Max-Age=${Math.floor(this.maxAge / 1000)}`,
            'HttpOnly',
            `SameSite=${this.sameSite}`
        ];
        if (this.secure) {
            attributes.push('Secure');
        }
        return attributes.join('; ');
    }

    attach(req, res) {
        const cookies = parseCookies(req.headers.cookie || '');
        let sessionId = cookies[this.cookieName];
        let sessionData = {};
        let dirty = false;

        if (sessionId) {
            const record = this.store.get(sessionId);
            if (record && record.expires > Date.now()) {
                sessionData = record.data;
            } else {
                this.store.delete(sessionId);
                sessionId = null;
            }
        }

        const proxy = new Proxy(sessionData, {
            set: (target, key, value) => {
                if (target[key] !== value) {
                    dirty = true;
                }
                target[key] = value;
                return true;
            },
            deleteProperty: (target, key) => {
                if (key in target) {
                    dirty = true;
                    delete target[key];
                }
                return true;
            }
        });

        req.session = proxy;
        req._sessionMeta = { id: sessionId, dirty: () => dirty, data: sessionData };

        req.ensureSession = () => {
            if (!req._sessionMeta.id) {
                req._sessionMeta.id = randomUUID();
            }
            dirty = true;
            return req._sessionMeta.id;
        };
    }

    commit(req, res) {
        if (!req._sessionMeta || req._sessionDestroyed) {
            return;
        }

        const shouldPersist = req._sessionMeta.id || req._sessionMeta.dirty();

        if (!shouldPersist) {
            return;
        }

        if (!req._sessionMeta.id) {
            req._sessionMeta.id = randomUUID();
        }

        this.store.set(req._sessionMeta.id, {
            data: { ...req.session },
            expires: Date.now() + this.maxAge
        });

        res.appendHeader('Set-Cookie', this._buildCookie(req._sessionMeta.id));
    }

    destroy(req, res) {
        if (req._sessionMeta?.id) {
            this.store.delete(req._sessionMeta.id);
        }
        req._sessionDestroyed = true;
        req.session = {};
        res.appendHeader('Set-Cookie', `${this.cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=${this.sameSite}`);
    }
}

class NativeApp {
    constructor({ sessionManager, bodyLimit = BODY_LIMIT_BYTES } = {}) {
        this.routes = [];
        this.staticMounts = [];
        this.sessionManager = sessionManager;
        this.bodyLimit = bodyLimit;
        this.server = null;
    }

    static(prefix, directory) {
        const normalized = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
        this.staticMounts.push({
            prefix: normalized,
            directory: path.resolve(directory)
        });
    }

    register(method, routePath, handlers) {
        const { regex, keys } = this._compileRoute(routePath);
        this.routes.push({
            method,
            regex,
            keys,
            handlers
        });
    }

    get(path, ...handlers) {
        this.register('GET', path, handlers);
    }

    post(path, ...handlers) {
        this.register('POST', path, handlers);
    }

    put(path, ...handlers) {
        this.register('PUT', path, handlers);
    }

    delete(path, ...handlers) {
        this.register('DELETE', path, handlers);
    }

    patch(path, ...handlers) {
        this.register('PATCH', path, handlers);
    }

    _compileRoute(routePath) {
        if (routePath === '/') {
            return { regex: /^\/$/, keys: [] };
        }

        const segments = routePath.split('/').filter(Boolean);
        const keys = [];
        const pattern = segments.map(segment => {
            if (segment.startsWith(':')) {
                keys.push(segment.slice(1));
                return '([^/]+)';
            }
            return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }).join('/');

        return {
            regex: new RegExp(`^/${pattern}/?$`),
            keys
        };
    }

    listen(port, callback) {
        this.server = http.createServer(this._handleRequest.bind(this));
        this.server.listen(port, callback);
    }

    close() {
        if (this.server) {
            this.server.close();
        }
    }

    async _handleRequest(nodeReq, nodeRes) {
        let req;
        let sessionCommitted = false;
        const res = new ResponseWrapper(nodeRes, {
            beforeSend: () => {
                if (!sessionCommitted && this.sessionManager) {
                    this.sessionManager.commit(req, res);
                    sessionCommitted = true;
                }
            }
        });
        const reqUrl = new URL(nodeReq.url, `http://${nodeReq.headers.host || "localhost"}`);
        req = {
            raw: nodeReq,
            method: (nodeReq.method || 'GET').toUpperCase(),
            headers: nodeReq.headers,
            url: reqUrl,
            pathname: reqUrl.pathname || '/',
            query: Object.fromEntries(reqUrl.searchParams.entries()),
            params: {},
            body: {},
            cookies: parseCookies(nodeReq.headers.cookie || ''),
            isMultipart: false
        };

        const corsAllowed = applyCorsHeaders(req, res);
        if (!corsAllowed) {
            res.status(403).json({ error: 'Not allowed by CORS' });
            return;
        }

        if (req.method === 'OPTIONS') {
            res.status(204).send('');
            return;
        }

        if (this.sessionManager) {
            this.sessionManager.attach(req, res);
        }

        try {
            await this._parseBody(req);
        } catch (error) {
            res.status(error.message === 'Payload too large' ? 413 : 400).json({ error: error.message });
            return;
        }

        if (await this._tryStatic(req, res)) {
            if (this.sessionManager && !sessionCommitted) {
                this.sessionManager.commit(req, res);
                sessionCommitted = true;
            }
            return;
        }

        const match = this._matchRoute(req.method, req.pathname);
        if (!match) {
            res.status(404).json({ error: 'Not found' });
            if (this.sessionManager && !sessionCommitted) {
                this.sessionManager.commit(req, res);
                sessionCommitted = true;
            }
            return;
        }

        req.params = match.params;

        try {
            await this._runHandlers(match.handlers, req, res);
        } catch (error) {
            console.error('Request error:', error);
            if (!res.ended) {
                res.status(500).json({ error: 'Internal server error' });
            }
        }

        if (this.sessionManager && !sessionCommitted) {
            this.sessionManager.commit(req, res);
            sessionCommitted = true;
        }
    }

    async _parseBody(req) {
        if (['GET', 'HEAD'].includes(req.method)) {
            req.body = {};
            return;
        }

        const contentType = req.headers['content-type'] || '';

        if (!contentType) {
            req.body = {};
            return;
        }

        if (contentType.startsWith('multipart/form-data')) {
            req.isMultipart = true;
            req.body = {};
            return;
        }

        const raw = await readRequestBody(req.raw, this.bodyLimit);
        if (raw.length === 0) {
            req.body = {};
            return;
        }

        if (contentType.includes('application/json')) {
            try {
                req.body = JSON.parse(raw.toString());
            } catch (error) {
                throw new Error('Invalid JSON payload');
            }
            return;
        }

        if (contentType.includes('application/x-www-form-urlencoded')) {
            req.body = querystring.parse(raw.toString());
            return;
        }

        req.body = raw;
    }

    async _tryStatic(req, res) {
        if (!STATIC_METHODS.includes(req.method)) {
            return false;
        }

        for (const mount of this.staticMounts) {
            if (req.pathname === mount.prefix || req.pathname.startsWith(`${mount.prefix}/`)) {
                const remainder = req.pathname.slice(mount.prefix.length);
                const relativePath = remainder.replace(/^\/+/, '');
                const safeRelative = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
                const filePath = path.join(mount.directory, safeRelative);

                if (!filePath.startsWith(mount.directory)) {
                    continue;
                }

                try {
                    const stats = await fs.promises.stat(filePath);
                    if (stats.isDirectory()) {
                        continue;
                    }

                    res.status(200);
                    res.setHeader('Content-Type', getMimeType(filePath));
                    const stream = fs.createReadStream(filePath);
                    stream.on('error', () => {
                        if (!res.ended) {
                            res.status(500).json({ error: 'Failed to read file' });
                        }
                    });
                    stream.pipe(res.raw);
                    res.ended = true;
                    return true;
                } catch (error) {
                    continue;
                }
            }
        }

        return false;
    }

    _matchRoute(method, pathname) {
        for (const route of this.routes) {
            if (route.method !== method) continue;
            const match = route.regex.exec(pathname);
            if (!match) continue;
            const params = {};
            route.keys.forEach((key, index) => {
                params[key] = decodeURIComponent(match[index + 1]);
            });
            return { handlers: route.handlers, params };
        }
        return null;
    }

    async _runHandlers(handlers, req, res) {
        const run = async (index) => {
            if (index >= handlers.length || res.ended) {
                return;
            }

            const handler = handlers[index];

            if (handler.length >= 3) {
                let nextCalled = false;
                const next = (err) => {
                    nextCalled = true;
                    if (err) {
                        throw err instanceof Error ? err : new Error(String(err));
                    }
                };

                try {
                    const result = handler(req, res, next);
                    if (result && typeof result.then === 'function') {
                        await result;
                    }
                } catch (error) {
                    throw error;
                }

                if (nextCalled && !res.ended) {
                    await run(index + 1);
                }
                return;
            }

            try {
                await handler(req, res);
            } catch (error) {
                throw error;
            }
            if (!res.ended) {
                await run(index + 1);
            }
        };

        await run(0);
    }
}

const ai = new GoogleGenerativeAI(process.env.API_KEY);
const model = 'gemini-2.5-flash';

const sessionManager = new SessionManager({
    cookieName: SESSION_COOKIE_NAME,
    maxAge: SESSION_TTL,
    sameSite: 'Lax',
    secure: false
});

const app = new NativeApp({
    sessionManager,
    bodyLimit: BODY_LIMIT_BYTES
});

const PORT = process.env.PORT;

//const apiSourceUrl = process.env.API_URL
//const apiKey = process.env.PLANT_ID_API_KEY;
//const LATITUDE = parseFloat(process.env.LATITUDE);
//const LONGITUDE = parseFloat(process.env.LONGITUDE);

const baseUploadsDir = path.join(__dirname, '..', 'images', 'uploads');
const forumDir = path.join(baseUploadsDir, 'forum');
const diseasesDir = path.join(baseUploadsDir, 'diseases');
const guidesDir = path.join(baseUploadsDir, 'guides');

[baseUploadsDir, forumDir, diseasesDir, guidesDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

const allowedImageTypes = /jpeg|jpg|png|webp/;
const DEFAULT_FILE_LIMIT = 5 * 1024 * 1024;

const uploadDirectoryMap = {
    forum: forumDir,
    disease: diseasesDir,
    diseases: diseasesDir,
    guide: guidesDir,
    guides: guidesDir
};

async function parseMultipartUpload(req, {
    uploadType,
    fieldName = 'image',
    required = false,
    maxFileSize = DEFAULT_FILE_LIMIT
} = {}) {
    if (!req.isMultipart) {
        throw new Error('Content-Type must be multipart/form-data');
    }

    if (req._uploadParsed) {
        return req._uploadParsed;
    }

    const targetDir = uploadDirectoryMap[uploadType] || baseUploadsDir;

    return new Promise((resolve, reject) => {
        const fields = {};
        let storedFile = null;
        let fileWritePromise = Promise.resolve();

        const busboy = Busboy({
            headers: req.headers,
            limits: { fileSize: maxFileSize, files: 1 }
        });

        busboy.on('field', (name, value) => {
            fields[name] = value;
        });

        busboy.on('file', (fieldname, file, infoOrFilename, legacyEncoding, legacyMimetype) => {
            let filename = '';
            let encoding = legacyEncoding;
            let mimetype = legacyMimetype;

            if (infoOrFilename && typeof infoOrFilename === 'object' && 'filename' in infoOrFilename) {
                filename = infoOrFilename.filename || '';
                encoding = infoOrFilename.encoding || encoding;
                mimetype = infoOrFilename.mimeType || infoOrFilename.mimetype || mimetype;
            } else {
                filename = infoOrFilename || '';
            }
            mimetype = mimetype || '';

            if (fieldName && fieldname !== fieldName) {
                file.resume();
                return;
            }

            const ext = path.extname(filename || '').toLowerCase();
            const isMimeValid = allowedImageTypes.test((mimetype || '').toLowerCase());
            const isExtValid = allowedImageTypes.test(ext);

            if (!isMimeValid || !isExtValid) {
                file.resume();
                busboy.emit('error', new Error('Only image files are allowed!'));
                return;
            }

            const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
            const finalName = `${uploadType || 'upload'}-${uniqueSuffix}${ext}`;
            const absolutePath = path.join(targetDir, finalName);
            const relativePath = `/images/uploads/${uploadType || 'generic'}/${finalName}`;
            let size = 0;

            storedFile = {
                fieldname,
                originalname: filename,
                filename: finalName,
                path: absolutePath,
                mimetype,
                size,
                relativePath
            };

            fileWritePromise = new Promise((fileResolve, fileReject) => {
                const writeStream = fs.createWriteStream(absolutePath);

                file.on('data', (chunk) => {
                    size += chunk.length;
                    storedFile.size = size;
                });

                file.on('limit', () => {
                    writeStream.destroy();
                    fs.unlink(absolutePath, () => {});
                    fileReject(new Error('File size must be less than 5MB'));
                });

                writeStream.on('finish', fileResolve);
                writeStream.on('error', fileReject);

                file.pipe(writeStream);
            }).catch((error) => {
                storedFile = null;
                throw error;
            });
        });

        busboy.on('finish', async () => {
            try {
                await fileWritePromise;
            } catch (error) {
                reject(error);
                return;
            }

            if (required && !storedFile) {
                reject(new Error('No image file uploaded.'));
                return;
            }

            req.body = fields;
            req.file = storedFile || null;
            req._uploadParsed = { fields, file: storedFile };
            resolve(req._uploadParsed);
        });

        busboy.on('error', (error) => {
            reject(error);
        });

        req.raw.pipe(busboy);
    });
}

function deleteImageFile(imagePath) {
    if (!imagePath) return;

    let fullPath;

    if (path.isAbsolute(imagePath)) {
        fullPath = imagePath;
    } else if (imagePath.startsWith('/images/')) {
        fullPath = path.join(__dirname, '..', imagePath);
    } else {
        fullPath = path.join(__dirname, '..', 'images', imagePath);
    }

    if (fs.existsSync(fullPath)) {
        try {
            fs.unlinkSync(fullPath);
        } catch (err) {
            console.error('Error deleting image:', err);
        }
    }
}

function getRelativePath(file, uploadType) {
    if (!file) return null;
    if (file.relativePath) return file.relativePath;
    return `/images/uploads/${uploadType}/${file.filename}`;
}

app.static('/images', path.join(__dirname, '..', 'images'));
app.static('/css', path.join(__dirname, '..', 'css'));
app.static('/js', path.join(__dirname, '..', 'js'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('/forum.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'forum.html'));
});

app.get('/guides.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'guides.html'));
});

app.get('/diseases.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'diseases.html'));
});

app.get('/about.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'about.html'));
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection()
    .then(conn => {
        console.log('✓ Connected to MariaDB database');
        conn.release();
    })
    .catch(err => {
        console.error('Database connection failed!!!:', err);
    });

const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
};

const isAdmin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const [users] = await pool.query(
            'SELECT role FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (users.length === 0 || users[0].role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        next();
    } catch (error) {
        console.error('Admin check error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
    }
};

function fileToGenerativePart(buffer, mimeType) {
    return {
        inlineData: {
            data: buffer.toString("base64"),
            mimeType
        },
    };
}

const diseaseResponseSchema = {
    type: SchemaType.OBJECT,
    properties: {
        plant_name: {
            type: SchemaType.STRING,
            description: "The most likely species or type of plant detected in the image.",
        },
        diseases: {
            type: SchemaType.ARRAY,
            description: "A list of diseases detected and their information.",
            items: {
                type: SchemaType.OBJECT,
                properties: {
                    name: {
                        type: SchemaType.STRING,
                        description: "The name of the disease, or 'Healthy' if no major disease is detected."
                    },
                    probability: {
                        type: SchemaType.NUMBER,
                        description: "The model's confidence probability (from 0.0 to 1.0) for this specific disease."
                    },
                    remedy: {
                        type: SchemaType.STRING,
                        description: "A specific, concise step-by-step remedy or care instruction for the detected condition."
                    }
                },
                required: ["name", "probability", "remedy"]
            }
        }
    },
    required: ["plant_name", "diseases"]
};

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (username.length < 3) {
        return res.status(400).json({ error: 'Username must have least 3 characters' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must have least 6 characters' });
    }

    try {
        const [existing] = await pool.query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existing.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const [result] = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, passwordHash]
        );

        req.session.userId = result.insertId;
        req.session.username = username;

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: { id: result.insertId, username }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const [users] = await pool.query(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({
            success: true,
            message: 'Login successful',
            user: { id: user.id, username: user.username }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;

        if (!subject || !message) {
            return res.status(400).json({
                success: false,
                error: 'All marked fields are required'
            });
        }

        const finalName = name || 'Anonymous';
        const finalEmail = email || 'Anonymous';

        await pool.query(
            `INSERT INTO contact_messages (name, email, subject, message) 
             VALUES (?, ?, ?, ?)`,
            [finalName, finalEmail, subject, message]
        );

        res.json({
            success: true,
            message: 'Your message has been received. We\'ll get back to you soon!'
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send message. Please try again later.'
        });
    }
});

app.post('/api/logout', (req, res) => {
    sessionManager.destroy(req, res);
    res.json({ success: true, message: 'Logout successful' });
});

async function initializeDiseaseAnalysesTable() {
}

initializeDiseaseAnalysesTable();

app.post('/api/analyze-disease', async (req, res) => {
    try {
        await parseMultipartUpload(req, {
            uploadType: 'disease',
            fieldName: 'image',
            required: true
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No image file uploaded.' });
    }

    let analysisId = null;
    const imagePath = getRelativePath(req.file, 'disease');

    try {
        //analysis record in db
        const [result] = await pool.query(
            `INSERT INTO disease_analyses (image_path, status) VALUES (?, 'processing')`,
            [imagePath]
        );
        analysisId = result.insertId;

        res.json({
            success: true,
            analysisId: analysisId,
            message: 'Analysis started. Use the analysisId to fetch results.'
        });

        // Process analysis asynchronously
        (async () => {
            try {
                const imageBuffer = fs.readFileSync(req.file.path);
                const imagePart = fileToGenerativePart(imageBuffer, req.file.mimetype);
                const prompt = process.env.PROMPT;

                //console.log(`[Analysis ${analysisId}] Prompt:`, prompt);
                const genModel = ai.getGenerativeModel({
                    model: model,
                    generationConfig: {
                        responseMimeType: "application/json",
                        responseSchema: diseaseResponseSchema,
                        temperature: 0.1,
                    }
                });

                const result = await genModel.generateContent([
                    prompt,
                    imagePart
                ]);

                const response = await result.response;
                const responseText = response.text();

                const diseaseData = JSON.parse(responseText);
                //console.log(`[Analysis ${analysisId}] Parsed disease data:`, JSON.stringify(diseaseData, null, 2));
                //console.log(`[Analysis ${analysisId}] Results stored in database`);

                /* Store results in database*/
                await pool.query(
                    `UPDATE disease_analyses 
                     SET plant_name = ?, result_data = ?, status = 'completed' 
                     WHERE id = ?`,
                    [diseaseData.plant_name, JSON.stringify(diseaseData), analysisId]
                );

                // Delete the temporary file after processing
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error(`[Analysis ${analysisId}] Error deleting temp file:`, err);
                });

            } catch (error) {
                console.error(`[Analysis ${analysisId}] Error with Gemini API or JSON parsing:`, error);
                console.error(`[Analysis ${analysisId}] Error stack:`, error.stack);

                await pool.query(
                    `UPDATE disease_analyses 
                     SET status = 'error', error_message = ? 
                     WHERE id = ?`,
                    [error.message, analysisId]
                );

                if (req.file && req.file.path) {
                    fs.unlink(req.file.path, (err) => {
                        if (err) console.error(`[Analysis ${analysisId}] Error deleting temp file on error:`, err);
                    });
                }
            }
        })();

    } catch (error) {
        console.error('Error creating analysis record:', error);

        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting temp file:", err);
            });
        }

        res.status(500).json({
            error: 'Failed to start analysis.',
            details: error.message
        });
    }
});

/* Endpoint to fetch analysis results */
app.get('/api/analyze-disease/:id', async (req, res) => {
    const analysisId = req.params.id;

    try {
        const [analyses] = await pool.query(
            'SELECT * FROM disease_analyses WHERE id = ?',
            [analysisId]
        );

        if (analyses.length === 0) {
            return res.status(404).json({ error: 'Analysis not found' });
        }

        const analysis = analyses[0];

        if (analysis.status === 'processing') {
            return res.json({
                status: 'processing',
                message: 'Analysis is still in progress'
            });
        }

        if (analysis.status === 'error') {
            return res.json({
                status: 'error',
                error: analysis.error_message || 'Analysis failed'
            });
        }

        // Status is 'completed'
        const resultData = JSON.parse(analysis.result_data);
        // Return the result data with status, ensuring plant_name is included
        res.json({
            status: 'completed',
            plant_name: resultData.plant_name || analysis.plant_name,
            diseases: resultData.diseases || []
        });

    } catch (error) {
        console.error('Error fetching analysis:', error);
        res.status(500).json({ error: 'Failed to fetch analysis results' });
    }
});

app.get('/api/auth/status', async (req, res) => {
    if (req.session.userId) {
        try {
            const [users] = await pool.query(
                'SELECT id, username, role FROM users WHERE id = ?',
                [req.session.userId]
            );

            if (users.length > 0) {
                res.json({
                    authenticated: true,
                    user: {
                        id: users[0].id,
                        username: users[0].username,
                        isAdmin: users[0].role === 'admin',
                        role: users[0].role
                    }
                });
            } else {
                res.json({ authenticated: false });
            }
        } catch (error) {
            console.error('Auth status error:', error);
            res.json({ authenticated: false });
        }
    } else {
        res.json({ authenticated: false });
    }
});

app.get('/api/profile', isAuthenticated, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, username, email, created_at FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: users[0] });

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/forum/posts', async (req, res) => {
    const { category, sort, search } = req.query;

    try {
        let query = `
            SELECT 
                p.id,
                p.user_id,
                p.title,
                p.body,
                p.image_path,
                p.status,
                p.created_at,
                u.username,
                c.name as category_name,
                COUNT(DISTINCT cm.id) as comment_count
            FROM posts p
            JOIN users u ON p.user_id = u.id
            JOIN categories c ON p.category_id = c.id
            LEFT JOIN comments cm ON p.id = cm.post_id
        `;

        const conditions = [];
        const params = [];

        if (category && category !== 'all') {
            conditions.push('c.name = ?');
            params.push(category);
        }

        if (search) {
            conditions.push('(p.title LIKE ? OR p.body LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        query += ' GROUP BY p.id';

        switch (sort) {
            case 'newest':
                query += ' ORDER BY p.created_at DESC';
                break;
            case 'unanswered':
                query += ' ORDER BY p.status = "unanswered" DESC, p.created_at DESC';
                break;
            case 'answered':
                query += ' ORDER BY p.status = "answered" DESC, p.created_at DESC';
                break;
            default:
                query += ' ORDER BY p.created_at DESC';
        }

        const [posts] = await pool.query(query, params);
        res.json({ success: true, posts });

    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ error: 'Failed to fetch posts' });
    }
});

app.get('/api/forum/posts/:id', async (req, res) => {
    const postId = req.params.id;

    try {
        const [posts] = await pool.query(`
            SELECT 
                p.*,
                u.username,
                c.name as category_name
            FROM posts p
            JOIN users u ON p.user_id = u.id
            JOIN categories c ON p.category_id = c.id
            WHERE p.id = ?
        `, [postId]);

        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const [comments] = await pool.query(`
            SELECT 
                c.*,
                u.username
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        `, [postId]);

        //await pool.query('UPDATE posts SET views = views + 1 WHERE id = ?', [postId]);

        res.json({
            success: true,
            post: posts[0],
            comments
        });

    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ error: 'Failed to fetch post' });
    }
});

app.post('/api/forum/posts', isAuthenticated, async (req, res) => {
    try {
        if (req.isMultipart) {
            await parseMultipartUpload(req, {
                uploadType: 'forum',
                fieldName: 'image',
                required: false
            });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const { title, category, body } = req.body;
    const userId = req.session.userId;

    if (!title || !category || !body) {
        if (req.file) deleteImageFile(req.file.path);
        return res.status(400).json({ error: 'Title, category, and body are required' });
    }

    try {
        const [categories] = await pool.query('SELECT id FROM categories WHERE name = ?', [category]);

        if (categories.length === 0) {
            if (req.file) deleteImageFile(req.file.path);
            return res.status(400).json({ error: 'Invalid category' });
        }

        const categoryId = categories[0].id;
        const imagePath = req.file ? getRelativePath(req.file, 'forum') : null;

        const [result] = await pool.query(
            `INSERT INTO posts (user_id, category_id, title, body, image_path, status) 
             VALUES (?, ?, ?, ?, ?, 'unanswered')`,
            [userId, categoryId, title, body, imagePath]
        );

        const [posts] = await pool.query(`
            SELECT p.*, u.username, c.name as category_name
            FROM posts p
            JOIN users u ON p.user_id = u.id
            JOIN categories c ON p.category_id = c.id
            WHERE p.id = ?
        `, [result.insertId]);

        res.status(201).json({
            success: true,
            message: 'Post created successfully',
            post: posts[0]
        });
    } catch (error) {
        console.error('Error creating post:', error);
        if (req.file) deleteImageFile(req.file.path);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

app.post('/api/forum/comments', isAuthenticated, async (req, res) => {
    const { post_id, content} = req.body;
    const userId = req.session.userId;

    if (!post_id || !content) {
        return res.status(400).json({ error: 'Post ID and content are required' });
    }

    try {
        const [result] = await pool.query(
            `INSERT INTO comments (post_id, user_id, content) 
             VALUES (?, ?, ?)`,
            [post_id, userId || null, content]
        );

        await pool.query(
            `UPDATE posts 
             SET status = 'answered' 
             WHERE id = ? AND status = 'unanswered'`,
            [post_id]
        );

        const [comments] = await pool.query(`
            SELECT 
                c.*,
                u.username
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        `, [result.insertId]);

        res.status(201).json({
            success: true,
            message: 'Comment added successfully',
            comment: comments[0]
        });

    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Failed to create comment' });
    }
});


// Delete a post (only by the post owner)
app.delete('/api/forum/posts/:id', isAuthenticated, async (req, res) => {
    const postId = req.params.id;
    const userId = req.session.userId;

    try {
        const [posts] = await pool.query('SELECT id, user_id, image_path FROM posts WHERE id = ?', [postId]);

        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const [users] = await pool.query(
            'SELECT role FROM users WHERE id = ?',
            [userId]
        );
        const isAdmin = users.length > 0 && users[0].role === 'admin';

        if (posts[0].user_id !== userId && !isAdmin) {
            return res.status(403).json({ error: 'You can only delete your own posts (or be an admin)' });
        }

        deleteImageFile(posts[0].image_path);

        await pool.query('DELETE FROM comments WHERE post_id = ?', [postId]);
        await pool.query('DELETE FROM posts WHERE id = ?', [postId]);

        res.json({ success: true, message: 'Post deleted successfully' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

/* Delete a comment (only by the comment owner) */
app.delete('/api/forum/comments/:id', isAuthenticated, async (req, res) => {
    const commentId = req.params.id;
    const userId = req.session.userId;

    try {
        const [comments] = await pool.query(
            'SELECT id, user_id, post_id FROM comments WHERE id = ?',
            [commentId]
        );

        if (comments.length === 0) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        const [users] = await pool.query(
            'SELECT role FROM users WHERE id = ?',
            [userId]
        );
        const isAdmin = users.length > 0 && users[0].role === 'admin';

        if (comments[0].user_id !== userId && !isAdmin) {
            return res.status(403).json({ error: 'You can only delete your own comments (or be an admin)' });
        }

        const postId = comments[0].post_id;

        await pool.query('DELETE FROM comments WHERE id = ?', [commentId]);

        res.json({
            success: true,
            message: 'Comment deleted successfully',
            postId: postId
        });

    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ error: 'Failed to delete comment' });
    }
});

/* User account deletion */
app.delete('/api/user/account', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ error: 'Password confirmation is required' });
    }

    try {
        const [users] = await pool.query(
            'SELECT id, password_hash FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        const [posts] = await pool.query(
            'SELECT image_path FROM posts WHERE user_id = ? AND image_path IS NOT NULL',
            [userId]
        );

        //Delete associated images from filesystem
        posts.forEach(post => {
            if (post.image_path) {
                const fullPath = path.join(__dirname, '..', post.image_path);
                if (fs.existsSync(fullPath)) {
                    try {
                        fs.unlinkSync(fullPath);
                    } catch (err) {
                        console.error('Error deleting image:', err);
                    }
                }
            }
        });

        /* Delete comments & posts first, before account */
        await pool.query('DELETE FROM comments WHERE user_id = ?', [userId]);

        await pool.query('DELETE FROM posts WHERE user_id = ?', [userId]);

        await pool.query('DELETE FROM users WHERE id = ?', [userId]);

        sessionManager.destroy(req, res);
        res.json({
            success: true,
            message: 'Account deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

app.get('/api/forum/categories', async (req, res) => {
    try {
        const [categories] = await pool.query('SELECT * FROM categories ORDER BY name');
        res.json({ success: true, categories });
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
        const [users] = await pool.query(`
            SELECT 
                u.id,
                u.username,
                u.email,
                u.role,
                u.created_at,
                COUNT(DISTINCT p.id) as post_count,
                COUNT(DISTINCT c.id) as comment_count
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            LEFT JOIN comments c ON u.id = c.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `);

        res.json({ success: true, users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.delete('/api/admin/comments/:id', isAdmin, async (req, res) => {
    const commentId = req.params.id;

    try {
        const [comments] = await pool.query(
            'SELECT id, post_id FROM comments WHERE id = ?',
            [commentId]
        );

        if (comments.length === 0) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        const postId = comments[0].post_id;

        await pool.query('DELETE FROM comments WHERE id = ?', [commentId]);

        res.json({
            success: true,
            message: 'Comment deleted successfully by admin',
            postId: postId
        });

    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ error: 'Failed to delete comment' });
    }
});

app.delete('/api/admin/users/:id', isAdmin, async (req, res) => {
    const userId = parseInt(req.params.id);

    if (userId === req.session.userId) {
        return res.status(400).json({ error: 'You cannot delete your own account via admin panel' });
    }

    try {
        const [users] = await pool.query(
            'SELECT id FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const [posts] = await pool.query(
            'SELECT image_path FROM posts WHERE user_id = ? AND image_path IS NOT NULL',
            [userId]
        );

        // Delete associated images storage
        posts.forEach(post => {
            if (post.image_path) {
                const fullPath = path.join(__dirname, '..', post.image_path);
                if (fs.existsSync(fullPath)) {
                    try {
                        fs.unlinkSync(fullPath);
                    } catch (err) {
                        console.error('Error deleting image:', err);
                    }
                }
            }
        });

        await pool.query('DELETE FROM comments WHERE user_id = ?', [userId]);

        await pool.query('DELETE FROM posts WHERE user_id = ?', [userId]);

        await pool.query('DELETE FROM users WHERE id = ?', [userId]);

        res.json({
            success: true,
            message: 'User deleted successfully by admin'
        });

    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
        const [postCount] = await pool.query('SELECT COUNT(*) as count FROM posts');
        const [commentCount] = await pool.query('SELECT COUNT(*) as count FROM comments');
        const [diseaseCount] = await pool.query('SELECT COUNT(*) as count FROM diseases');
        const [guideCount] = await pool.query('SELECT COUNT(*) as count FROM guides');

        const [unansweredPosts] = await pool.query(
            "SELECT COUNT(*) as count FROM posts WHERE status = 'unanswered'"
        );

        const [activeUsers7d] = await pool.query(`
            SELECT COUNT(DISTINCT user_id) as count
            FROM (
                SELECT user_id FROM posts WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                UNION
                SELECT user_id FROM comments WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ) as active
        `);

        const [activeUsers30d] = await pool.query(`
            SELECT COUNT(DISTINCT user_id) as count
            FROM (
                SELECT user_id FROM posts WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                UNION
                SELECT user_id FROM comments WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            ) as active
        `);

        const [retention7d] = await pool.query(`
            SELECT 
                COUNT(DISTINCT u.id) as total_eligible,
                COUNT(DISTINCT active.user_id) as active_users
            FROM users u
            LEFT JOIN (
                SELECT DISTINCT user_id 
                FROM posts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                UNION
                SELECT DISTINCT user_id 
                FROM comments 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ) active ON u.id = active.user_id AND active.user_id IS NOT NULL
            WHERE u.created_at <= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `);

        const [retention30d] = await pool.query(`
            SELECT 
                COUNT(DISTINCT u.id) as total_eligible,
                COUNT(DISTINCT active.user_id) as active_users
            FROM users u
            LEFT JOIN (
                SELECT DISTINCT user_id 
                FROM posts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                UNION
                SELECT DISTINCT user_id 
                FROM comments 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            ) active ON u.id = active.user_id AND active.user_id IS NOT NULL
            WHERE u.created_at <= DATE_SUB(NOW(), INTERVAL 30 DAY)
        `);

        const retentionRate7d = retention7d[0].total_eligible > 0
            ? ((retention7d[0].active_users / retention7d[0].total_eligible) * 100).toFixed(1)
            : 'N/A';

        const retentionRate30d = retention30d[0].total_eligible > 0
            ? ((retention30d[0].active_users / retention30d[0].total_eligible) * 100).toFixed(1)
            : 'N/A';

        res.json({
            success: true,
            stats: {
                totalUsers: Number(userCount[0].count),
                totalPosts: Number(postCount[0].count),
                totalComments: Number(commentCount[0].count),
                totalDiseases: Number(diseaseCount[0].count),
                totalGuides: Number(guideCount[0].count),
                unansweredPosts: Number(unansweredPosts[0].count),
                activeUsers7d: Number(activeUsers7d[0].count),
                activeUsers30d: Number(activeUsers30d[0].count),
                retentionRate7d: retentionRate7d,
                retentionRate30d: retentionRate30d,
                /* Additional context for debugging */
                eligibleUsers7d: retention7d[0].total_eligible,
                eligibleUsers30d: retention30d[0].total_eligible
            }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.listen(PORT, () => {
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ API available at http://localhost:${PORT}/api`);
});

process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    app.close();
    await pool.end();
    process.exit(0);
});

app.get('/api/diseases', async (req, res) => {
    try {
        const [diseases] = await pool.query(`
            SELECT d.*, u.username as created_by_username
            FROM diseases d
            LEFT JOIN users u ON d.created_by = u.id
            ORDER BY d.created_at DESC
        `);

        res.json({ success: true, diseases });
    } catch (error) {
        console.error('Error fetching diseases:', error);
        res.status(500).json({ error: 'Failed to fetch diseases' });
    }
});

// Get single disease
app.get('/api/diseases/:id', async (req, res) => {
    try {
        const [diseases] = await pool.query(
            'SELECT * FROM diseases WHERE id = ?',
            [req.params.id]
        );

        if (diseases.length === 0) {
            return res.status(404).json({ error: 'Disease not found' });
        }

        res.json({ success: true, disease: diseases[0] });
    } catch (error) {
        console.error('Error fetching disease:', error);
        res.status(500).json({ error: 'Failed to fetch disease' });
    }
});

app.post('/api/diseases', isAdmin, async (req, res) => {
    try {
        if (req.isMultipart) {
            await parseMultipartUpload(req, {
                uploadType: 'diseases',
                fieldName: 'image',
                required: false
            });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const { name, causes, affects, symptoms, treatment, prevention } = req.body;
    const userId = req.session.userId;

    if (!name) {
        if (req.file) deleteImageFile(req.file.path);
        return res.status(400).json({ error: 'Name is required' });
    }

    try {
        const imagePath = req.file ? getRelativePath(req.file, 'diseases') : null;

        const [result] = await pool.query(
            `INSERT INTO diseases (name, image_path, causes, affects, symptoms, treatment, prevention, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, imagePath, causes, affects, symptoms, treatment, prevention, userId]
        );

        const [diseases] = await pool.query('SELECT * FROM diseases WHERE id = ?', [result.insertId]);

        res.status(201).json({
            success: true,
            message: 'Disease created successfully',
            disease: diseases[0]
        });
    } catch (error) {
        console.error('Error creating disease:', error);
        if (req.file) deleteImageFile(req.file.path);
        res.status(500).json({ error: 'Failed to create disease' });
    }
});

app.put('/api/diseases/:id', isAdmin, async (req, res) => {
    try {
        if (req.isMultipart) {
            await parseMultipartUpload(req, {
                uploadType: 'diseases',
                fieldName: 'image',
                required: false
            });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const diseaseId = req.params.id;
    const { name, causes, affects, symptoms, treatment, prevention } = req.body;

    try {
        const [existing] = await pool.query('SELECT * FROM diseases WHERE id = ?', [diseaseId]);

        if (existing.length === 0) {
            if (req.file) deleteImageFile(req.file.path);
            return res.status(404).json({ error: 'Disease not found' });
        }

        let imagePath = existing[0].image_path;

        if (req.file) {
            deleteImageFile(imagePath);
            imagePath = getRelativePath(req.file, 'diseases');
        }

        await pool.query(
            `UPDATE diseases 
             SET name = ?, image_path = ?, causes = ?, affects = ?, symptoms = ?, treatment = ?, prevention = ?
             WHERE id = ?`,
            [name, imagePath, causes, affects, symptoms, treatment, prevention, diseaseId]
        );

        const [updated] = await pool.query('SELECT * FROM diseases WHERE id = ?', [diseaseId]);

        res.json({
            success: true,
            message: 'Disease updated successfully',
            disease: updated[0]
        });
    } catch (error) {
        console.error('Error updating disease:', error);
        if (req.file) deleteImageFile(req.file.path);
        res.status(500).json({ error: 'Failed to update disease' });
    }
});

app.delete('/api/diseases/:id', isAdmin, async (req, res) => {
    const diseaseId = req.params.id;

    try {
        const [diseases] = await pool.query('SELECT * FROM diseases WHERE id = ?', [diseaseId]);

        if (diseases.length === 0) {
            return res.status(404).json({ error: 'Disease not found' });
        }

        deleteImageFile(diseases[0].image_path);
        await pool.query('DELETE FROM diseases WHERE id = ?', [diseaseId]);

        res.json({ success: true, message: 'Disease deleted successfully' });
    } catch (error) {
        console.error('Error deleting disease:', error);
        res.status(500).json({ error: 'Failed to delete disease' });
    }
});

app.get('/api/guides', async (req, res) => {
    try {
        const [guides] = await pool.query(`
            SELECT g.*, u.username as created_by_username
            FROM guides g
            LEFT JOIN users u ON g.created_by = u.id
            ORDER BY g.created_at DESC
        `);

        res.json({ success: true, guides });
    } catch (error) {
        console.error('Error fetching guides:', error);
        res.status(500).json({ error: 'Failed to fetch guides' });
    }
});

app.get('/api/guides/:id', async (req, res) => {
    try {
        const [guides] = await pool.query(
            'SELECT * FROM guides WHERE id = ?',
            [req.params.id]
        );

        if (guides.length === 0) {
            return res.status(404).json({ error: 'Guide not found' });
        }

        res.json({ success: true, guide: guides[0] });
    } catch (error) {
        console.error('Error fetching guide:', error);
        res.status(500).json({ error: 'Failed to fetch guide' });
    }
});

// Create, update and delete guide
app.post('/api/guides', isAdmin, async (req, res) => {
    try {
        if (req.isMultipart) {
            await parseMultipartUpload(req, {
                uploadType: 'guides',
                fieldName: 'image',
                required: false
            });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const { name, planting_suggestions, care_instructions } = req.body;
    const userId = req.session.userId;

    if (!name) {
        if (req.file) deleteImageFile(req.file.path);
        return res.status(400).json({ error: 'Name is required' });
    }

    try {
        const imagePath = req.file ? getRelativePath(req.file, 'guides') : null;

        const [result] = await pool.query(
            `INSERT INTO guides (name, image_path, planting_suggestions, care_instructions, created_by)
             VALUES (?, ?, ?, ?, ?)`,
            [name, imagePath, planting_suggestions, care_instructions, userId]
        );

        const [guides] = await pool.query('SELECT * FROM guides WHERE id = ?', [result.insertId]);

        res.status(201).json({
            success: true,
            message: 'Guide created successfully',
            guide: guides[0]
        });
    } catch (error) {
        console.error('Error creating guide:', error);
        if (req.file) deleteImageFile(req.file.path);
        res.status(500).json({ error: 'Failed to create guide' });
    }
});

app.put('/api/guides/:id', isAdmin, async (req, res) => {
    try {
        if (req.isMultipart) {
            await parseMultipartUpload(req, {
                uploadType: 'guides',
                fieldName: 'image',
                required: false
            });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const guideId = req.params.id;
    const { name, planting_suggestions, care_instructions } = req.body;

    try {
        const [existing] = await pool.query('SELECT * FROM guides WHERE id = ?', [guideId]);

        if (existing.length === 0) {
            if (req.file) deleteImageFile(req.file.path);
            return res.status(404).json({ error: 'Guide not found' });
        }

        let imagePath = existing[0].image_path;

        if (req.file) {
            // Delete old image if exists
            if (imagePath && imagePath.startsWith('/images/uploads/')) {
                const oldPath = path.join(__dirname, '..', imagePath);
                if (fs.existsSync(oldPath)) {
                    fs.unlinkSync(oldPath);
                }
            }
            imagePath = getRelativePath(req.file, 'guides');
        }

        await pool.query(
            `UPDATE guides 
             SET name = ?, image_path = ?, planting_suggestions = ?, care_instructions = ?
             WHERE id = ?`,
            [name, imagePath, planting_suggestions, care_instructions, guideId]
        );

        const [updated] = await pool.query('SELECT * FROM guides WHERE id = ?', [guideId]);

        res.json({
            success: true,
            message: 'Guide updated successfully',
            guide: updated[0]
        });
    } catch (error) {
        console.error('Error updating guide:', error);
        if (req.file) deleteImageFile(req.file.path);
        res.status(500).json({ error: 'Failed to update guide' });
    }
});

app.delete('/api/guides/:id', isAdmin, async (req, res) => {
    const guideId = req.params.id;

    try {
        const [guides] = await pool.query('SELECT * FROM guides WHERE id = ?', [guideId]);

        if (guides.length === 0) {
            return res.status(404).json({ error: 'Guide not found' });
        }

        // Delete image if exists
        const imagePath = guides[0].image_path;
        deleteImageFile(imagePath);

        await pool.query('DELETE FROM guides WHERE id = ?', [guideId]);

        res.json({
            success: true,
            message: 'Guide deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting guide:', error);
        res.status(500).json({ error: 'Failed to delete guide' });
    }
});

/* stats for stats div in landing page */
app.post('/api/stats', async (req, res) => {
    const numOfUsers = req.query.users === 'true';
    const numOfGuides = req.query.guidesCount === 'true';
    const numOfDiseases = req.query.diseaseCount === 'true';

    try {
        const stats = {};

        if (numOfUsers) {
            const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = "user"');
            stats.totalUsers = Number(userCount[0].count);
        }
        if (numOfGuides) {
            const [guideCount] = await pool.query('SELECT COUNT(*) as count FROM guides');
            stats.totalGuides = Number(guideCount[0].count);
        }
        if (numOfDiseases) {
            const [diseaseCount] = await pool.query('SELECT COUNT(*) as count FROM diseases');
            stats.totalDiseases = Number(diseaseCount[0].count);
        }

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/user/report', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;

    try {
        const [users] = await pool.query(
            'SELECT id, username, email, created_at FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        const [posts] = await pool.query(`
            SELECT 
                p.id,
                p.title,
                p.body,
                p.image_path,
                p.created_at,
                c.name as category_name,
                COUNT(DISTINCT cm.id) as comment_count
            FROM posts p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN comments cm ON p.id = cm.post_id
            WHERE p.user_id = ?
            GROUP BY p.id
            ORDER BY p.created_at DESC
        `, [userId]);

        const [comments] = await pool.query(`
            SELECT 
                c.id,
                c.content,
                c.created_at,
                p.title as post_title,
                p.id as post_id
            FROM comments c
            LEFT JOIN posts p ON c.post_id = p.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        `, [userId]);

        const totalPosts = posts.length;
        const totalComments = comments.length;
        //const totalViews = posts.reduce((sum, post) => sum + (post.views || 0), 0);

        const report = {
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                created_at: user.created_at
            },
            stats: {
                totalPosts,
                totalComments,
                //totalViews
            },
            posts: posts.map(post => ({
                id: post.id,
                title: post.title,
                body: post.body,
                image_path: post.image_path,
                category_name: post.category_name,
                //views: post.views,
                comment_count: parseInt(post.comment_count),
                created_at: post.created_at
            })),
            comments: comments.map(comment => ({
                id: comment.id,
                content: comment.content,
                post_title: comment.post_title,
                post_id: comment.post_id,
                created_at: comment.created_at
            }))
        };

        res.json({
            success: true,
            report
        });

    } catch (error) {
        console.error('Error generating user report:', error);
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

app.get('/api/admin/contact-messages', isAdmin, async (req, res) => {
    try {
        const [messages] = await pool.query(`
            SELECT 
                id,
                name,
                email,
                subject,
                message,
                read_status,
                created_at
            FROM contact_messages
            ORDER BY read_status ASC, created_at DESC
        `);

        res.json({ success: true, messages });
    } catch (error) {
        console.error('Error fetching contact messages:', error);
        res.status(500).json({ error: 'Failed to fetch contact messages' });
    }
});

app.get('/api/admin/contact-messages/unread-count', isAdmin, async (req, res) => {
    try {
        const [result] = await pool.query(`
            SELECT COUNT(*) as count 
            FROM contact_messages 
            WHERE read_status = FALSE
        `);

        res.json({ success: true, unreadCount: result[0].count });
    } catch (error) {
        console.error('Error fetching unread count:', error);
        res.status(500).json({ error: 'Failed to fetch unread count' });
    }
});

app.patch('/api/admin/contact-messages/:id/read', isAdmin, async (req, res) => {
    const messageId = req.params.id;

    try {
        await pool.query(
            'UPDATE contact_messages SET read_status = TRUE WHERE id = ?',
            [messageId]
        );

        res.json({ success: true, message: 'Message marked as read' });
    } catch (error) {
        console.error('Error marking message as read:', error);
        res.status(500).json({ error: 'Failed to mark message as read' });
    }
});

app.delete('/api/admin/contact-messages/:id', isAdmin, async (req, res) => {
    const messageId = req.params.id;

    try {
        await pool.query('DELETE FROM contact_messages WHERE id = ?', [messageId]);

        res.json({ success: true, message: 'Message deleted successfully' });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});