/**
 * WebShield 3D Interactive Geodesic Defense Shield Engine
 * Apex Institute of Technology & Cyber Sciences
 * 
 * Powered by Three.js (WebGL)
 * Visualizes real-time IAM states, mouse parallax, strike warnings,
 * WAF deflections, and 24-hour crimson lockout containment.
 */

class WebShield3D {
  constructor(canvasId = 'shield-canvas') {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.warn(`[WebShield3D] Canvas element #${canvasId} not found.`);
      return;
    }

    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.animationFrameId = null;

    // 3D Visual Objects
    this.shieldGroup = null;
    this.outerWireframe = null;
    this.innerFacetShield = null;
    this.innerCore = null;
    this.coreAura = null;
    this.orbitingPackets = [];
    this.shockwaveRings = [];
    this.starField = null;

    // Mouse Tracking & Parallax
    this.mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
    this.windowHalfX = window.innerWidth / 2;
    this.windowHalfY = window.innerHeight / 2;

    // State & Color Matrix
    this.currentState = 'CYAN_IDLE'; // CYAN_IDLE, AMBER_PULSE, SOLAR_WARNING, CRIMSON_LOCKOUT, EMERALD_VERIFIED
    this.colorPalette = {
      CYAN_IDLE: {
        wireframe: 0x00F5D4,
        facets: 0x4361EE,
        core: 0x00F5D4,
        aura: 0x7B2CBF,
        particles: 0x38BDF8,
        pulseSpeed: 1.0
      },
      AMBER_PULSE: {
        wireframe: 0xFFB703,
        facets: 0xFB8500,
        core: 0xFFB703,
        aura: 0x9D0208,
        particles: 0xFFD166,
        pulseSpeed: 2.2
      },
      SOLAR_WARNING: {
        wireframe: 0xFFB703,
        facets: 0xE85D04,
        core: 0xFF7B00,
        aura: 0x6A040F,
        particles: 0xFFA200,
        pulseSpeed: 3.5
      },
      CRIMSON_LOCKOUT: {
        wireframe: 0xFF0055,
        facets: 0x990033,
        core: 0xFF0055,
        aura: 0x4D001A,
        particles: 0xFF3366,
        pulseSpeed: 5.0
      },
      EMERALD_VERIFIED: {
        wireframe: 0x10B981,
        facets: 0x059669,
        core: 0x34D399,
        aura: 0x047857,
        particles: 0x6EE7B7,
        pulseSpeed: 1.8
      }
    };

    // Material References for Live Tweens
    this.materials = {};
    this.clock = new THREE.Clock();

    this.init();
  }

  init() {
    // 1. Scene Setup
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x050816, 0.035);

    // 2. Camera Setup
    const aspect = window.innerWidth / window.innerHeight;
    this.camera = new THREE.PerspectiveCamera(50, aspect, 0.1, 1000);
    this.camera.position.z = 18;

    // 3. WebGL Renderer
    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(window.innerWidth, window.innerHeight);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.25;

    // 4. Lighting Rig
    this.setupLighting();

    // 5. Construct 3D Shield Artifacts
    this.buildGeodesicShield();
    this.buildDataPackets();
    this.buildDeepSpaceAmbience();

    // 6. Bind Events
    this.bindEvents();

    // 7. Start Render Loop
    this.animate();
  }

  setupLighting() {
    const ambientLight = new THREE.AmbientLight(0x0A0F2C, 2.5);
    this.scene.add(ambientLight);

    this.pointLightCyan = new THREE.PointLight(0x00F5D4, 3, 35);
    this.pointLightCyan.position.set(10, 10, 10);
    this.scene.add(this.pointLightCyan);

    this.pointLightViolet = new THREE.PointLight(0x7B2CBF, 3, 35);
    this.pointLightViolet.position.set(-10, -10, -5);
    this.scene.add(this.pointLightViolet);

    this.centerCoreLight = new THREE.PointLight(0x00F5D4, 2, 20);
    this.centerCoreLight.position.set(0, 0, 0);
    this.scene.add(this.centerCoreLight);
  }

  buildGeodesicShield() {
    this.shieldGroup = new THREE.Group();

    // A. Outer Geodesic Hexagonal Wireframe (Icosahedron detail 2)
    const icosaGeo = new THREE.IcosahedronGeometry(5.2, 2);

    this.materials.wireframe = new THREE.MeshBasicMaterial({
      color: this.colorPalette.CYAN_IDLE.wireframe,
      wireframe: true,
      transparent: true,
      opacity: 0.85
    });

    this.outerWireframe = new THREE.Mesh(icosaGeo, this.materials.wireframe);
    this.shieldGroup.add(this.outerWireframe);

    // B. Inner Translucent Facet Geodesic Layer
    this.materials.facets = new THREE.MeshStandardMaterial({
      color: this.colorPalette.CYAN_IDLE.facets,
      roughness: 0.15,
      metalness: 0.85,
      transparent: true,
      opacity: 0.28,
      flatShading: true,
      side: THREE.DoubleSide
    });

    this.innerFacetShield = new THREE.Mesh(new THREE.IcosahedronGeometry(4.8, 1), this.materials.facets);
    this.shieldGroup.add(this.innerFacetShield);

    // C. Central Holographic Core (Apex Crystalline Node)
    const coreGeo = new THREE.OctahedronGeometry(2.0, 1);
    this.materials.core = new THREE.MeshStandardMaterial({
      color: this.colorPalette.CYAN_IDLE.core,
      emissive: this.colorPalette.CYAN_IDLE.core,
      emissiveIntensity: 0.6,
      roughness: 0.2,
      metalness: 0.9,
      wireframe: false
    });
    this.innerCore = new THREE.Mesh(coreGeo, this.materials.core);
    this.shieldGroup.add(this.innerCore);

    // D. Core Aura (Inner glowing sphere)
    const auraGeo = new THREE.SphereGeometry(2.4, 24, 24);
    this.materials.aura = new THREE.MeshBasicMaterial({
      color: this.colorPalette.CYAN_IDLE.aura,
      transparent: true,
      opacity: 0.2,
      wireframe: true
    });
    this.coreAura = new THREE.Mesh(auraGeo, this.materials.aura);
    this.shieldGroup.add(this.coreAura);

    this.scene.add(this.shieldGroup);
  }

  buildDataPackets() {
    // Orbiting encrypted packets around the geodesic shield
    const packetCount = 48;
    const packetGeo = new THREE.BoxGeometry(0.18, 0.18, 0.4);
    this.materials.packets = new THREE.MeshBasicMaterial({
      color: this.colorPalette.CYAN_IDLE.particles,
      transparent: true,
      opacity: 0.9
    });

    for (let i = 0; i < packetCount; i++) {
      const packet = new THREE.Mesh(packetGeo, this.materials.packets);
      const orbitRadius = 6.0 + Math.random() * 2.5;
      const speed = (0.5 + Math.random() * 0.8) * (Math.random() > 0.5 ? 1 : -1);
      const angle = Math.random() * Math.PI * 2;
      const inclination = (Math.random() - 0.5) * Math.PI;

      this.orbitingPackets.push({
        mesh: packet,
        radius: orbitRadius,
        speed,
        angle,
        inclination
      });

      this.scene.add(packet);
    }
  }

  buildDeepSpaceAmbience() {
    // Ambient Starfield
    const starCount = 600;
    const starGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(starCount * 3);

    for (let i = 0; i < starCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 80;
      positions[i + 1] = (Math.random() - 0.5) * 80;
      positions[i + 2] = -10 + (Math.random() - 0.5) * 50;
    }

    starGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const starMat = new THREE.PointsMaterial({
      color: 0x38BDF8,
      size: 0.15,
      transparent: true,
      opacity: 0.6
    });

    this.starField = new THREE.Points(starGeo, starMat);
    this.scene.add(this.starField);
  }

  bindEvents() {
    window.addEventListener('resize', this.onWindowResize.bind(this), false);
    window.addEventListener('mousemove', this.onMouseMove.bind(this), false);
  }

  onWindowResize() {
    this.windowHalfX = window.innerWidth / 2;
    this.windowHalfY = window.innerHeight / 2;

    this.camera.aspect = window.innerWidth / window.innerHeight;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(window.innerWidth, window.innerHeight);
  }

  onMouseMove(event) {
    this.mouse.targetX = (event.clientX - this.windowHalfX) / this.windowHalfX;
    this.mouse.targetY = (event.clientY - this.windowHalfY) / this.windowHalfY;
  }

  /**
   * Keyboard typing reaction: triggers micro-frequency ripple on the shield
   */
  onTyping() {
    if (this.shieldGroup) {
      this.shieldGroup.rotation.y += 0.08;
      this.innerCore.scale.set(1.15, 1.15, 1.15);
      setTimeout(() => {
        if (this.innerCore) this.innerCore.scale.set(1, 1, 1);
      }, 100);
    }
  }

  /**
   * Live WAF Deflection Effect (Creates red/crimson expanding deflection shockwave)
   */
  triggerDeflection() {
    const ringGeo = new THREE.RingGeometry(4.5, 5.2, 48);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xFF0055,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 1.0
    });

    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 2;
    this.scene.add(ring);

    this.shockwaveRings.push({
      mesh: ring,
      scale: 1,
      opacity: 1.0
    });

    // Momentary camera shake
    this.camera.position.x += (Math.random() - 0.5) * 0.4;
    this.camera.position.y += (Math.random() - 0.5) * 0.4;
    setTimeout(() => {
      this.camera.position.set(0, 0, 18);
    }, 150);
  }

  /**
   * Change Shield State & Smoothly Transition Colors
   * @param {string} state - CYAN_IDLE | AMBER_PULSE | SOLAR_WARNING | CRIMSON_LOCKOUT | EMERALD_VERIFIED
   */
  setShieldState(state) {
    if (!this.colorPalette[state]) return;
    this.currentState = state;
    const colors = this.colorPalette[state];

    // Smoothly apply target colors
    if (this.materials.wireframe) this.materials.wireframe.color.setHex(colors.wireframe);
    if (this.materials.facets) this.materials.facets.color.setHex(colors.facets);
    if (this.materials.core) {
      this.materials.core.color.setHex(colors.core);
      this.materials.core.emissive.setHex(colors.core);
    }
    if (this.materials.aura) this.materials.aura.color.setHex(colors.aura);
    if (this.materials.packets) this.materials.packets.color.setHex(colors.particles);
    if (this.centerCoreLight) this.centerCoreLight.color.setHex(colors.core);
  }

  animate() {
    this.animationFrameId = requestAnimationFrame(this.animate.bind(this));

    const delta = this.clock.getDelta();
    const time = this.clock.getElapsedTime();
    const currentSpeedMultiplier = this.colorPalette[this.currentState]?.pulseSpeed || 1.0;

    // 1. Mouse Parallax Easing
    this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.05;
    this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.05;

    // 2. Shield Rotations
    if (this.shieldGroup) {
      this.shieldGroup.rotation.y += 0.35 * delta * currentSpeedMultiplier;
      this.shieldGroup.rotation.x = this.mouse.y * 0.25;
      this.shieldGroup.rotation.z = -this.mouse.x * 0.25;

      // Pulse breathing
      const pulse = Math.sin(time * 2 * currentSpeedMultiplier) * 0.04 + 1.0;
      this.outerWireframe.scale.set(pulse, pulse, pulse);

      // Core counter-rotation
      if (this.innerCore) {
        this.innerCore.rotation.x += 0.6 * delta * currentSpeedMultiplier;
        this.innerCore.rotation.y -= 0.8 * delta * currentSpeedMultiplier;
      }

      if (this.coreAura) {
        this.coreAura.rotation.y += 0.2 * delta;
      }
    }

    // 3. Orbiting Data Packets
    for (const p of this.orbitingPackets) {
      p.angle += p.speed * delta * (0.8 + currentSpeedMultiplier * 0.2);
      p.mesh.position.x = Math.cos(p.angle) * p.radius;
      p.mesh.position.z = Math.sin(p.angle) * p.radius;
      p.mesh.position.y = Math.sin(p.angle * 2) * Math.sin(p.inclination) * 2.5;
      p.mesh.lookAt(0, 0, 0);
    }

    // 4. Update Deflection Shockwave Rings
    for (let i = this.shockwaveRings.length - 1; i >= 0; i--) {
      const ring = this.shockwaveRings[i];
      ring.scale += delta * 6.5;
      ring.opacity -= delta * 1.8;
      ring.mesh.scale.set(ring.scale, ring.scale, ring.scale);
      ring.mesh.material.opacity = ring.opacity;

      if (ring.opacity <= 0) {
        this.scene.remove(ring.mesh);
        ring.mesh.geometry.dispose();
        ring.mesh.material.dispose();
        this.shockwaveRings.splice(i, 1);
      }
    }

    // 5. Starfield Rotation
    if (this.starField) {
      this.starField.rotation.y = time * 0.015;
    }

    // Render Frame
    this.renderer.render(this.scene, this.camera);
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    window.removeEventListener('resize', this.onWindowResize);
    window.removeEventListener('mousemove', this.onMouseMove);
    if (this.renderer) {
      this.renderer.dispose();
    }
  }
}

// Export for browser global scope
window.WebShield3D = WebShield3D;





