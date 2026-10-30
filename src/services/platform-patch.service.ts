/**
 * PlatformPatchService
 * Generates drop-in server configuration hardening patches for multiple production platforms:
 * Nginx, Apache HTTPd (.htaccess), Caddy, Express.js (Node), and Django / Flask (Python).
 */
export class PlatformPatchService {
  public static generatePlatformPatch(
    findingTitle: string,
    cwe: string,
    targetUrl: string,
    platform: 'nginx' | 'apache' | 'caddy' | 'express' | 'django' = 'nginx'
  ): { filename: string; contentType: string; content: string } {
    const genTime = new Date().toISOString();
    const plat = platform.toLowerCase();

    switch (plat) {
      case 'nginx':
        return {
          filename: `sential-nginx-hardening.conf`,
          contentType: 'text/plain',
          content: `# ==============================================================================
# Sential AI Production Hardening & Remediation Configuration
# Finding: ${findingTitle} (${cwe})
# Target: ${targetUrl}
# Generated: ${genTime}
# Platform: Nginx (nginx.conf / sites-available)
# ==============================================================================

server {
    # 1. Prevent MIME-Type Sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # 2. Prevent Clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # 3. HTTP Strict Transport Security (HSTS)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # 4. Content Security Policy (Contextual Output Protection)
    add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; object-src 'none'; base-uri 'self';" always;

    # 5. Referrer Policy & Permissions
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # 6. Hide Nginx Version Information
    server_tokens off;

    # 7. Block Access to Hidden Configuration Files (.env, .git, .aws, etc.)
    location ~ /\\.(?!well-known) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # 8. Limit Buffer & Request Body Size (DoS & Buffer Overflow Protection)
    client_body_buffer_size 128k;
    client_max_body_size 50M;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
}
`,
        };

      case 'apache':
        return {
          filename: `sential-apache-hardening.htaccess`,
          contentType: 'text/plain',
          content: `# ==============================================================================
# Sential AI Production Hardening Configuration
# Finding: ${findingTitle} (${cwe})
# Target: ${targetUrl}
# Generated: ${genTime}
# Platform: Apache HTTP Server (.htaccess)
# ==============================================================================

<IfModule mod_headers.c>
    # 1. Protective Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header always set Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; object-src 'none';"
</IfModule>

# 2. Hide Apache Server Version & Signatures
ServerSignature Off

# 3. Block Hidden & Configuration Files
<FilesMatch "^\\.(?!well-known)">
    Order allow,deny
    Deny from all
</FilesMatch>

# 4. Block Sensitive Extension Disclosure
<FilesMatch "\\.(env|git|sql|bak|yml|yaml|ini|log|sh|conf)$">
    Order allow,deny
    Deny from all
</FilesMatch>
`,
        };

      case 'caddy':
        return {
          filename: `sential-caddy-hardening.Caddyfile`,
          contentType: 'text/plain',
          content: `# ==============================================================================
# Sential AI Production Hardening Configuration
# Finding: ${findingTitle} (${cwe})
# Target: ${targetUrl}
# Generated: ${genTime}
# Platform: Caddy Web Server (Caddyfile)
# ==============================================================================

(security_headers) {
    header {
        # Strict Transport Security (HSTS)
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        # Clickjacking & Sniffing Mitigation
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), camera=(), microphone=()"
        Content-Security-Policy "default-src 'self' https:; object-src 'none';"
        # Remove Server Identity
        -Server
    }
}

# Block hidden files
@hidden {
    path */.*
    not path */.well-known/*
}
respond @hidden 404
`,
        };

      case 'express':
        return {
          filename: `sential-express-security.js`,
          contentType: 'text/javascript',
          content: `// ==============================================================================
// Sential AI Production Hardening Middleware
// Finding: ${findingTitle} (${cwe})
// Target: ${targetUrl}
// Generated: ${genTime}
// Platform: Node.js (Express.js)
// ==============================================================================

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

module.exports = function configureAppSecurity(app) {
  // 1. Comprehensive HTTP Security Headers via Helmet
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false,
    frameguard: { action: 'sameorigin' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
  }));

  // 2. Automated Rate Limiting on Authentication Endpoints (Brute-Force Shield)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per window
    message: { error: 'Too many login attempts, please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use('/api/auth/', authLimiter);
  app.use('/login', authLimiter);

  // 3. Disable Express Server Footprint
  app.disable('x-powered-by');
};
`,
        };

      case 'django':
      default:
        return {
          filename: `sential-django-security.py`,
          contentType: 'text/x-python',
          content: `# ==============================================================================
# Sential AI Production Hardening Configuration
# Finding: ${findingTitle} (${cwe})
# Target: ${targetUrl}
# Generated: ${genTime}
# Platform: Python (Django settings.py)
# ==============================================================================

# 1. SSL/TLS & Redirect Enforcement
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# 2. Strict Transport Security (HSTS)
SECURE_HSTS_SECONDS = 31536000  # 1 Year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# 3. Cookies & Session Hardening
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# 4. MIME & Clickjacking Defenses
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'SAMEORIGIN'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
`,
        };
    }
  }
}
