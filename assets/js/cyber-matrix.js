/**
 * SENTIAL AI - EXECUTIVE CYBER CONSTELLATION & TRANQUIL THREAT MESH
 * Zen-style calm, professional, and elegant neural particle network.
 * Stratified even distribution, ultra-smooth zero-gravity drift, hairline filaments, 
 * ambient cursor illumination & subtle synaptic pulses.
 */

(function(window) {
    'use strict';

    class CyberMatrixEngine {
        constructor() {
            this.canvases = new Map();
            this.mouse = { x: -1000, y: -1000, active: false };
            this.targetMouse = { x: -1000, y: -1000 };
            this.isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            this.animationFrame = null;
            this.lastTime = 0;
            this.initGlobalListeners();
        }

        initGlobalListeners() {
            window.addEventListener('mousemove', (e) => {
                this.targetMouse.x = e.clientX;
                this.targetMouse.y = e.clientY;
                this.mouse.active = true;
            });

            window.addEventListener('mouseleave', () => {
                this.mouse.active = false;
                this.targetMouse.x = -1000;
                this.targetMouse.y = -1000;
            });

            window.addEventListener('click', (e) => {
                this.triggerRipple(e.clientX, e.clientY);
            });

            window.addEventListener('resize', () => {
                this.canvases.forEach((instance) => {
                    this.resizeInstance(instance);
                });
            });

            // Watch for theme changes
            const observer = new MutationObserver(() => {
                const dark = document.documentElement.getAttribute('data-theme') === 'dark';
                if (dark !== this.isDark) {
                    this.isDark = dark;
                    this.updateThemeColors();
                }
            });
            observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        }

        attach(canvasId, options = {}) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;

            if (this.canvases.has(canvasId)) {
                this.destroy(canvasId);
            }

            const ctx = canvas.getContext('2d');
            const instance = {
                id: canvasId,
                canvas,
                ctx,
                options: Object.assign({
                    nodeCount: window.innerWidth < 768 ? 28 : 54,
                    maxDistance: window.innerWidth < 768 ? 120 : 165,
                    mouseRadius: 175,
                    packetCount: 5,
                    drawPackets: true,
                    ambientLight: true
                }, options),
                nodes: [],
                packets: [],
                ripples: [],
                width: 0,
                height: 0,
                dpr: Math.min(window.devicePixelRatio || 1, 2)
            };

            this.resizeInstance(instance);
            this.initNodes(instance);
            this.canvases.set(canvasId, instance);

            if (!this.animationFrame) {
                this.animate();
            }

            return instance;
        }

        destroy(canvasId) {
            if (this.canvases.has(canvasId)) {
                this.canvases.delete(canvasId);
            }
            if (this.canvases.size === 0 && this.animationFrame) {
                cancelAnimationFrame(this.animationFrame);
                this.animationFrame = null;
            }
        }

        resizeInstance(instance) {
            const rect = instance.canvas.parentElement ? 
                instance.canvas.parentElement.getBoundingClientRect() : 
                { width: window.innerWidth, height: window.innerHeight };

            const w = Math.max(rect.width, 320);
            const h = Math.max(rect.height, 320);

            instance.width = w;
            instance.height = h;
            instance.dpr = Math.min(window.devicePixelRatio || 1, 2);

            instance.canvas.width = w * instance.dpr;
            instance.canvas.height = h * instance.dpr;
            instance.canvas.style.width = `${w}px`;
            instance.canvas.style.height = `${h}px`;

            instance.ctx.scale(instance.dpr, instance.dpr);
        }

        initNodes(instance) {
            instance.nodes = [];
            const count = instance.options.nodeCount;
            const w = instance.width;
            const h = instance.height;

            // Stratified grid distribution to guarantee uniform, balanced, elegant coverage across the entire viewport
            const cols = window.innerWidth < 768 ? 5 : 8;
            const rows = window.innerWidth < 768 ? 4 : 5;
            const cellW = w / cols;
            const cellH = h / rows;

            let index = 0;
            for (let r = 0; r < rows; r++) {
                for (let c = 0; c < cols; c++) {
                    if (index >= count) break;
                    
                    const isAnchor = index % 6 === 0;
                    const angle = Math.random() * Math.PI * 2;
                    const speed = 0.08 + Math.random() * 0.12;

                    // Place within cell with organic jitter padding
                    const x = c * cellW + 0.15 * cellW + Math.random() * (0.7 * cellW);
                    const y = r * cellH + 0.15 * cellH + Math.random() * (0.7 * cellH);

                    instance.nodes.push({
                        x,
                        y,
                        vx: Math.cos(angle) * speed,
                        vy: Math.sin(angle) * speed,
                        radius: isAnchor ? (2.0 + Math.random() * 0.5) : (1.0 + Math.random() * 0.5),
                        isAnchor,
                        pulsePhase: Math.random() * Math.PI * 2,
                        pulseSpeed: 0.012 + Math.random() * 0.016,
                        baseAlpha: isAnchor ? 0.75 : (0.28 + Math.random() * 0.35)
                    });
                    index++;
                }
            }

            // Fill any remaining nodes organically
            while (instance.nodes.length < count) {
                const isAnchor = instance.nodes.length % 6 === 0;
                const angle = Math.random() * Math.PI * 2;
                const speed = 0.08 + Math.random() * 0.12;
                instance.nodes.push({
                    x: Math.random() * w,
                    y: Math.random() * h,
                    vx: Math.cos(angle) * speed,
                    vy: Math.sin(angle) * speed,
                    radius: isAnchor ? (2.0 + Math.random() * 0.5) : (1.0 + Math.random() * 0.5),
                    isAnchor,
                    pulsePhase: Math.random() * Math.PI * 2,
                    pulseSpeed: 0.012 + Math.random() * 0.016,
                    baseAlpha: isAnchor ? 0.75 : (0.28 + Math.random() * 0.35)
                });
            }

            // Subtle Synaptic Energy Pulses (Few, calm, and slow)
            instance.packets = [];
            if (instance.options.drawPackets) {
                for (let p = 0; p < instance.options.packetCount; p++) {
                    const pkt = this.createPacket(instance);
                    if (pkt) instance.packets.push(pkt);
                }
            }
        }

        createPacket(instance) {
            const count = instance.nodes.length;
            if (count < 2) return null;
            const fromIndex = Math.floor(Math.random() * count);
            let toIndex = Math.floor(Math.random() * count);
            while (toIndex === fromIndex) {
                toIndex = Math.floor(Math.random() * count);
            }
            return {
                fromIndex,
                toIndex,
                progress: Math.random(),
                speed: 0.0035 + Math.random() * 0.0045 // Calm, slow flow (silky smooth)
            };
        }

        triggerRipple(clientX, clientY) {
            this.canvases.forEach(instance => {
                const rect = instance.canvas.getBoundingClientRect();
                const x = clientX - rect.left;
                const y = clientY - rect.top;
                if (x >= 0 && x <= instance.width && y >= 0 && y <= instance.height) {
                    instance.ripples.push({
                        x,
                        y,
                        radius: 4,
                        maxRadius: Math.min(instance.width, instance.height) * 0.35,
                        alpha: 0.45
                    });

                    // Very gentle nudge to nearby nodes (no violent shaking)
                    instance.nodes.forEach(node => {
                        const dx = node.x - x;
                        const dy = node.y - y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 140 && dist > 1) {
                            const force = (140 - dist) / 140 * 1.2;
                            node.vx += (dx / dist) * force * 0.35;
                            node.vy += (dy / dist) * force * 0.35;
                        }
                    });
                }
            });
        }

        updateThemeColors() {
            if (!this.isDark) {
                this.canvases.forEach(instance => {
                    instance.ctx.clearRect(0, 0, instance.width, instance.height);
                });
            }
        }

        animate() {
            // Silky smooth mouse interpolation
            this.mouse.x += (this.targetMouse.x - this.mouse.x) * 0.08;
            this.mouse.y += (this.targetMouse.y - this.mouse.y) * 0.08;

            this.canvases.forEach(instance => {
                this.renderInstance(instance);
            });

            this.animationFrame = requestAnimationFrame(() => this.animate());
        }

        renderInstance(instance) {
            const ctx = instance.ctx;
            const w = instance.width;
            const h = instance.height;
            const nodes = instance.nodes;
            const maxDist = instance.options.maxDistance;
            const maxDistSq = maxDist * maxDist;

            ctx.clearRect(0, 0, w, h);

            // Strictly render Cyber Constellation matrix in Dark Mode ONLY
            if (!this.isDark) {
                return;
            }

            // Get canvas-relative mouse position
            const rect = instance.canvas.getBoundingClientRect();
            const mouseX = this.mouse.x - rect.left;
            const mouseY = this.mouse.y - rect.top;
            const isMouseInside = this.mouse.active && mouseX >= -60 && mouseX <= w + 60 && mouseY >= -60 && mouseY <= h + 60;

            // 1. Soft Ambient Cursor Spotlight (Calm, luminous luxury glow)
            if (isMouseInside && instance.options.ambientLight) {
                const ambientGrad = ctx.createRadialGradient(mouseX, mouseY, 0, mouseX, mouseY, instance.options.mouseRadius);
                ambientGrad.addColorStop(0, 'rgba(56, 189, 248, 0.045)');
                ambientGrad.addColorStop(0.5, 'rgba(56, 189, 248, 0.015)');
                ambientGrad.addColorStop(1, 'rgba(56, 189, 248, 0)');
                ctx.fillStyle = ambientGrad;
                ctx.beginPath();
                ctx.arc(mouseX, mouseY, instance.options.mouseRadius, 0, Math.PI * 2);
                ctx.fill();
            }

            // 2. Soft Zen Ripples on click
            for (let s = instance.ripples.length - 1; s >= 0; s--) {
                const rip = instance.ripples[s];
                rip.radius += 2.2;
                rip.alpha *= 0.965;
                if (rip.alpha < 0.015 || rip.radius >= rip.maxRadius) {
                    instance.ripples.splice(s, 1);
                    continue;
                }
                ctx.beginPath();
                ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);
                ctx.strokeStyle = `rgba(56, 189, 248, ${rip.alpha * 0.35})`;
                ctx.lineWidth = 1;
                ctx.stroke();
            }

            // 3. Update Node Positions with zero-gravity calm physics
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];

                n.x += n.vx;
                n.y += n.vy;

                // Gentle damping to keep movement serene
                n.vx *= 0.994;
                n.vy *= 0.994;
                if (Math.abs(n.vx) < 0.06) n.vx += (Math.random() - 0.5) * 0.03;
                if (Math.abs(n.vy) < 0.06) n.vy += (Math.random() - 0.5) * 0.03;

                // Soft toroidal screen wrapping with 30px offscreen buffer
                if (n.x < -30) n.x = w + 30;
                else if (n.x > w + 30) n.x = -30;
                if (n.y < -30) n.y = h + 30;
                else if (n.y > h + 30) n.y = -30;

                // Smooth, gentle cursor yielding (soft spring, never chaotic)
                if (isMouseInside) {
                    const dx = mouseX - n.x;
                    const dy = mouseY - n.y;
                    const distSq = dx * dx + dy * dy;
                    if (distSq < 100 * 100 && distSq > 4) {
                        const dist = Math.sqrt(distSq);
                        const force = (100 - dist) * 0.006;
                        n.x -= (dx / dist) * force;
                        n.y -= (dy / dist) * force;
                    }
                }

                // Breathing pulse
                n.pulsePhase += n.pulseSpeed;
            }

            // 4. Draw Hairline Constellation Lines
            for (let i = 0; i < nodes.length; i++) {
                const n1 = nodes[i];
                for (let j = i + 1; j < nodes.length; j++) {
                    const n2 = nodes[j];
                    const dx = n2.x - n1.x;
                    const dy = n2.y - n1.y;
                    const distSq = dx * dx + dy * dy;

                    if (distSq < maxDistSq) {
                        const dist = Math.sqrt(distSq);
                        // Quadratic falloff for silky smooth fading lines
                        const ratio = 1 - (dist / maxDist);
                        const alpha = (ratio * ratio) * 0.24; // Soft, delicate alpha

                        ctx.beginPath();
                        ctx.moveTo(n1.x, n1.y);
                        ctx.lineTo(n2.x, n2.y);

                        if (n1.isAnchor || n2.isAnchor) {
                            ctx.strokeStyle = `rgba(56, 189, 248, ${alpha * 1.35})`;
                            ctx.lineWidth = 0.75;
                        } else {
                            ctx.strokeStyle = `rgba(125, 211, 252, ${alpha * 0.85})`;
                            ctx.lineWidth = 0.55;
                        }
                        ctx.stroke();
                    }
                }

                // Interactive Mouse Connector Lines (Hairline, delicate)
                if (isMouseInside) {
                    const mdx = mouseX - n1.x;
                    const mdy = mouseY - n1.y;
                    const mDistSq = mdx * mdx + mdy * mdy;
                    const mouseThreshold = instance.options.mouseRadius;
                    if (mDistSq < mouseThreshold * mouseThreshold) {
                        const mDist = Math.sqrt(mDistSq);
                        const mRatio = 1 - (mDist / mouseThreshold);
                        const mAlpha = (mRatio * mRatio) * 0.35;

                        ctx.beginPath();
                        ctx.moveTo(n1.x, n1.y);
                        ctx.lineTo(mouseX, mouseY);
                        ctx.strokeStyle = `rgba(56, 189, 248, ${mAlpha})`;
                        ctx.lineWidth = 0.75;
                        ctx.stroke();
                    }
                }
            }

            // 5. Draw Subtle Synaptic Energy Pulses (Gliding smoothly along lines)
            if (instance.options.drawPackets && instance.packets) {
                for (let p = 0; p < instance.packets.length; p++) {
                    const pkt = instance.packets[p];
                    if (!pkt) continue;

                    const nFrom = nodes[pkt.fromIndex];
                    const nTo = nodes[pkt.toIndex];

                    if (!nFrom || !nTo) {
                        instance.packets[p] = this.createPacket(instance);
                        continue;
                    }

                    const dx = nTo.x - nFrom.x;
                    const dy = nTo.y - nFrom.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist > maxDist * 1.25) {
                        instance.packets[p] = this.createPacket(instance);
                        continue;
                    }

                    pkt.progress += pkt.speed;
                    if (pkt.progress >= 1) {
                        // Find connected neighbors near nTo
                        const neighbors = [];
                        for (let k = 0; k < nodes.length; k++) {
                            if (k !== pkt.toIndex) {
                                const ndx = nodes[k].x - nTo.x;
                                const ndy = nodes[k].y - nTo.y;
                                if (ndx * ndx + ndy * ndy < maxDistSq) {
                                    neighbors.push(k);
                                }
                            }
                        }
                        if (neighbors.length > 0) {
                            pkt.fromIndex = pkt.toIndex;
                            pkt.toIndex = neighbors[Math.floor(Math.random() * neighbors.length)];
                            pkt.progress = 0;
                        } else {
                            instance.packets[p] = this.createPacket(instance);
                            continue;
                        }
                    }

                    const px = nFrom.x + (nTo.x - nFrom.x) * pkt.progress;
                    const py = nFrom.y + (nTo.y - nFrom.y) * pkt.progress;

                    // Subtle, calm spark glow
                    ctx.beginPath();
                    ctx.arc(px, py, 1.8, 0, Math.PI * 2);
                    ctx.fillStyle = '#38bdf8';
                    ctx.shadowColor = '#38bdf8';
                    ctx.shadowBlur = 6;
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }
            }

            // 6. Draw Refined Particle Nodes
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                const pulse = Math.sin(n.pulsePhase) * 0.18;
                const currentAlpha = Math.min(Math.max(n.baseAlpha + pulse, 0.15), 0.95);

                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);

                if (n.isAnchor) {
                    // Anchor Beacons have a soft, calm halo
                    ctx.fillStyle = `rgba(224, 242, 254, ${currentAlpha})`;
                    ctx.shadowColor = '#38bdf8';
                    ctx.shadowBlur = 7;
                } else {
                    // Regular nodes are crisp micro-stars
                    ctx.fillStyle = `rgba(203, 213, 225, ${currentAlpha * 0.8})`;
                    ctx.shadowBlur = 0;
                }
                ctx.fill();
                ctx.shadowBlur = 0;
            }
        }
    }

    window.CyberMatrix = new CyberMatrixEngine();

})(window);
