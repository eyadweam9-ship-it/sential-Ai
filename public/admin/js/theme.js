// ==========================================================================
// SENTIAL AI — THEME MANAGER & ZEN CONSTELLATION ENGINE
// Handles Cyber Dark Mode (Deep Slate & Cyan) toggle and Landing Canvas
// ==========================================================================

const ThemeManager = {
    getTheme() {
        return localStorage.getItem('sential_theme') || 'dark';
    },

    setTheme(theme) {
        localStorage.setItem('sential_theme', theme);
        document.documentElement.setAttribute('data-theme', theme);
        if (document.body) {
            document.body.setAttribute('data-theme', theme);
        }
        this.updateButtons();
    },

    toggle() {
        const current = this.getTheme();
        const next = current === 'dark' ? 'light' : 'dark';
        this.setTheme(next);
    },

    getIconSvg(theme) {
        if (theme === 'dark') {
            // Sun icon (click to switch to Light)
            return `<svg class="theme-icon theme-icon-sun" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`;
        } else {
            // Moon icon (click to switch to Dark)
            return `<svg class="theme-icon theme-icon-moon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`;
        }
    },

    renderButton(extraClass = '') {
        const theme = this.getTheme();
        const isDark = theme === 'dark';
        const title = isDark ? 'Switch to Light Mode' : 'Switch to Cyber Dark Mode';
        return `<button type="button" class="theme-toggle-btn ${extraClass}" onclick="ThemeManager.toggle()" title="${title}" aria-label="${title}">${this.getIconSvg(theme)}</button>`;
    },

    updateButtons() {
        const theme = this.getTheme();
        const isDark = theme === 'dark';
        const title = isDark ? 'Switch to Light Mode' : 'Switch to Cyber Dark Mode';
        const svg = this.getIconSvg(theme);
        const buttons = document.querySelectorAll('.theme-toggle-btn');
        buttons.forEach(btn => {
            btn.title = title;
            btn.setAttribute('aria-label', title);
            btn.innerHTML = svg;
        });
    },

    init() {
        const theme = this.getTheme();
        document.documentElement.setAttribute('data-theme', theme);
        if (document.body) {
            document.body.setAttribute('data-theme', theme);
        }
        this.updateButtons();
    }
};

// Immediate early execution to prevent any theme flicker
ThemeManager.init();

// ==========================================================================
// ZEN CONSTELLATION PARTICLE SYSTEM (LANDING / WELCOME PAGE ONLY)
// Subtle, slow, delicate, and fully paused on internal pages
// ==========================================================================

const ZenConstellation = {
    canvas: null,
    ctx: null,
    animId: null,
    particles: [],
    width: 0,
    height: 0,
    mouse: { x: null, y: null, maxDist: 100 },
    handleResize: null,
    handleMouseMove: null,
    handleMouseLeave: null,

    init(canvasId = 'zen-constellation-canvas') {
        this.destroy(); // Safely teardown any previous instance

        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;

        this.ctx = this.canvas.getContext('2d');
        if (!this.ctx) return;

        const updateDimensions = () => {
            if (!this.canvas) return;
            const parent = this.canvas.parentElement || document.body;
            const rect = parent.getBoundingClientRect();
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            this.width = rect.width || window.innerWidth;
            this.height = rect.height || window.innerHeight;
            this.canvas.width = Math.floor(this.width * dpr);
            this.canvas.height = Math.floor(this.height * dpr);
            this.canvas.style.width = this.width + 'px';
            this.canvas.style.height = this.height + 'px';
            this.ctx.setTransform(1, 0, 0, 1, 0, 0);
            this.ctx.scale(dpr, dpr);
        };

        updateDimensions();
        this.handleResize = () => updateDimensions();
        window.addEventListener('resize', this.handleResize, { passive: true });

        this.handleMouseMove = (e) => {
            if (!this.canvas) return;
            const rect = this.canvas.getBoundingClientRect();
            this.mouse.x = e.clientX - rect.left;
            this.mouse.y = e.clientY - rect.top;
        };

        this.handleMouseLeave = () => {
            this.mouse.x = null;
            this.mouse.y = null;
        };

        window.addEventListener('mousemove', this.handleMouseMove, { passive: true });
        window.addEventListener('mouseleave', this.handleMouseLeave, { passive: true });

        // Initialize particles (slow, gentle, delicate count)
        const density = Math.min(Math.floor((this.width * this.height) / 24000), 50);
        const count = Math.max(density, 32);
        this.particles = [];

        for (let i = 0; i < count; i++) {
            this.particles.push({
                x: Math.random() * this.width,
                y: Math.random() * this.height,
                vx: (Math.random() - 0.5) * 0.3, // Soft zen drift
                vy: (Math.random() - 0.5) * 0.3,
                radius: 1.2 + Math.random() * 1.1,
                baseAlpha: 0.35 + Math.random() * 0.35,
                pulse: Math.random() * Math.PI * 2
            });
        }

        const maxDist = 115;

        const loop = () => {
            if (!this.ctx || !this.canvas) return;
            this.ctx.clearRect(0, 0, this.width, this.height);

            const isDark = (document.documentElement.getAttribute('data-theme') || 'dark') === 'dark';
            const particleRgb = isDark ? '56, 189, 248' : '37, 99, 235';

            for (let i = 0; i < this.particles.length; i++) {
                const p = this.particles[i];
                p.x += p.vx;
                p.y += p.vy;
                p.pulse += 0.02;

                // Screen edge wrap
                if (p.x < -10) p.x = this.width + 10;
                else if (p.x > this.width + 10) p.x = -10;
                if (p.y < -10) p.y = this.height + 10;
                else if (p.y > this.height + 10) p.y = -10;

                // Subtle mouse influence
                if (this.mouse.x !== null && this.mouse.y !== null) {
                    const dx = p.x - this.mouse.x;
                    const dy = p.y - this.mouse.y;
                    const dist = Math.hypot(dx, dy);
                    if (dist < this.mouse.maxDist && dist > 1) {
                        const force = (this.mouse.maxDist - dist) / this.mouse.maxDist;
                        p.x += (dx / dist) * force * 0.5;
                        p.y += (dy / dist) * force * 0.5;
                    }
                }

                const currentAlpha = p.baseAlpha + Math.sin(p.pulse) * 0.15;
                this.ctx.beginPath();
                this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                this.ctx.fillStyle = `rgba(${particleRgb}, ${Math.max(currentAlpha, 0.15)})`;
                this.ctx.fill();

                // Hairline constellation links
                for (let j = i + 1; j < this.particles.length; j++) {
                    const p2 = this.particles[j];
                    const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                    if (dist < maxDist) {
                        const lineAlpha = (1 - dist / maxDist) * (isDark ? 0.15 : 0.08);
                        this.ctx.beginPath();
                        this.ctx.moveTo(p.x, p.y);
                        this.ctx.lineTo(p2.x, p2.y);
                        this.ctx.strokeStyle = `rgba(${particleRgb}, ${lineAlpha})`;
                        this.ctx.lineWidth = 0.65;
                        this.ctx.stroke();
                    }
                }
            }

            this.animId = requestAnimationFrame(loop);
        };

        this.animId = requestAnimationFrame(loop);
    },

    destroy() {
        if (this.animId) {
            cancelAnimationFrame(this.animId);
            this.animId = null;
        }
        if (this.handleResize) {
            window.removeEventListener('resize', this.handleResize);
            this.handleResize = null;
        }
        if (this.handleMouseMove) {
            window.removeEventListener('mousemove', this.handleMouseMove);
            this.handleMouseMove = null;
        }
        if (this.handleMouseLeave) {
            window.removeEventListener('mouseleave', this.handleMouseLeave);
            this.handleMouseLeave = null;
        }
        this.canvas = null;
        this.ctx = null;
        this.particles = [];
    }
};

window.ThemeManager = ThemeManager;
window.ZenConstellation = ZenConstellation;

// Synchronize theme on DOMContentLoaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => ThemeManager.init());
} else {
    ThemeManager.init();
}
