/**
 * Apex Institute of Technology & Cyber Sciences
 * 3D Holographic Campus Globe & Interactive Department Nodes Engine
 * Powered by Three.js (WebGL)
 */

class ApexPortal3D {
  constructor(canvasId = 'portal-canvas') {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.warn(`[ApexPortal3D] Canvas element #${canvasId} not found.`);
      return;
    }

    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.animationFrameId = null;

    // 3D Objects
    this.monumentGroup = null;
    this.holographicGlobe = null;
    this.innerGridSphere = null;
    this.energyRings = [];
    this.departmentNodes = [];
    this.beamLines = [];
    this.baseGrid = null;

    // Interaction & Raycasting
    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2(-9999, -9999);
    this.isDragging = false;
    this.previousMousePosition = { x: 0, y: 0 };
    this.rotationVelocity = { x: 0.002, y: 0.004 };
    this.hoveredNode = null;

    this.clock = new THREE.Clock();

    // Department Specifications
    this.deptData = [
      {
        id: 'CYB',
        name: 'Cyber Defense & Quantum Warfare',
        color: 0x00F5D4,
        position: new THREE.Vector3(4.2, 1.8, 2.5),
        stats: '12 Research Labs | DEFCON 5 Clearance',
        icon: '🛡️'
      },
      {
        id: 'AIR',
        name: 'Autonomous AI & Neural Security',
        color: 0x4361EE,
        position: new THREE.Vector3(-4.2, 2.2, 1.5),
        stats: '14 Swarm Testing Ranges',
        icon: '🤖'
      },
      {
        id: 'QNT',
        name: 'Quantum Information Science & QKD',
        color: 0x7B2CBF,
        position: new THREE.Vector3(1.5, -3.2, 3.8),
        stats: '64 Quantum Entangled Nodes',
        icon: '⚛️'
      },
      {
        id: 'CLD',
        name: 'Cloud & Zero-Trust Infrastructure',
        color: 0xFFB703,
        position: new THREE.Vector3(-2.8, -2.4, -3.2),
        stats: 'MicroVM & eBPF Observability Vault',
        icon: '☁️'
      }
    ];

    this.init();
  }

  init() {
    // 1. Scene Setup
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x050816, 0.025);

    // 2. Camera Setup
    const aspect = this.canvas.clientWidth / this.canvas.clientHeight || 1;
    this.camera = new THREE.PerspectiveCamera(45, aspect, 0.1, 1000);
    this.camera.position.set(0, 3, 14);
    this.camera.lookAt(0, 0, 0);

    // 3. WebGL Renderer
    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(this.canvas.clientWidth, this.canvas.clientHeight);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // 4. Lighting Rig
    this.setupLighting();

    // 5. Build Holographic Campus Monument
    this.buildCampusMonument();
    this.buildDepartmentNodes();
    this.buildBaseGrid();

    // 6. Bind User Controls (Drag to rotate, hover raycaster)
    this.bindEvents();

    // 7. Render Loop
    this.animate();
  }

  setupLighting() {
    const ambientLight = new THREE.AmbientLight(0x0F172A, 2.0);
    this.scene.add(ambientLight);

    const light1 = new THREE.DirectionalLight(0x00F5D4, 2.5);
    light1.position.set(5, 10, 7);
    this.scene.add(light1);

    const light2 = new THREE.DirectionalLight(0x7B2CBF, 2.0);
    light2.position.set(-8, -5, -5);
    this.scene.add(light2);

    const coreLight = new THREE.PointLight(0x00F5D4, 3, 20);
    coreLight.position.set(0, 0, 0);
    this.scene.add(coreLight);
  }

  buildCampusMonument() {
    this.monumentGroup = new THREE.Group();

    // A. Central Holographic University Globe
    const globeGeo = new THREE.SphereGeometry(3.2, 32, 32);
    const globeMat = new THREE.MeshStandardMaterial({
      color: 0x0A1638,
      roughness: 0.1,
      metalness: 0.9,
      wireframe: true,
      transparent: true,
      opacity: 0.5
    });
    this.holographicGlobe = new THREE.Mesh(globeGeo, globeMat);
    this.monumentGroup.add(this.holographicGlobe);

    // B. Inner Glowing Quantum Core
    const coreGeo = new THREE.DodecahedronGeometry(1.6, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x00F5D4,
      wireframe: true,
      transparent: true,
      opacity: 0.75
    });
    this.innerCore = new THREE.Mesh(coreGeo, coreMat);
    this.monumentGroup.add(this.innerCore);

    // C. Orbiting Quantum Gyroscopic Rings
    for (let i = 0; i < 3; i++) {
      const ringGeo = new THREE.TorusGeometry(3.8 + i * 0.45, 0.03, 16, 100);
      const ringMat = new THREE.MeshBasicMaterial({
        color: i === 0 ? 0x00F5D4 : (i === 1 ? 0x4361EE : 0x7B2CBF),
        transparent: true,
        opacity: 0.65
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.rotation.x = (i * Math.PI) / 3;
      ring.rotation.y = (i * Math.PI) / 4;
      this.energyRings.push(ring);
      this.monumentGroup.add(ring);
    }

    this.scene.add(this.monumentGroup);
  }

  buildDepartmentNodes() {
    for (const data of this.deptData) {
      const nodeGroup = new THREE.Group();
      nodeGroup.position.copy(data.position);

      // Node Outer Diamond
      const nodeGeo = new THREE.OctahedronGeometry(0.55, 0);
      const nodeMat = new THREE.MeshStandardMaterial({
        color: data.color,
        emissive: data.color,
        emissiveIntensity: 0.5,
        roughness: 0.2,
        metalness: 0.8
      });
      const mesh = new THREE.Mesh(nodeGeo, nodeMat);
      mesh.userData = data; // Store department metadata
      nodeGroup.add(mesh);

      // Orbiting Node Pulse Ring
      const ringGeo = new THREE.RingGeometry(0.7, 0.8, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: data.color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.5
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      nodeGroup.add(ring);

      // Laser Beam Linking Core to Department Node
      const points = [new THREE.Vector3(0, 0, 0), data.position];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({
        color: data.color,
        transparent: true,
        opacity: 0.35
      });
      const beamLine = new THREE.Line(lineGeo, lineMat);
      this.monumentGroup.add(beamLine);

      nodeGroup.userData = {
        mesh,
        ring,
        baseScale: 1.0,
        data
      };

      this.departmentNodes.push(nodeGroup);
      this.monumentGroup.add(nodeGroup);
    }
  }

  buildBaseGrid() {
    const gridHelper = new THREE.GridHelper(20, 20, 0x00F5D4, 0x1E293B);
    gridHelper.position.y = -5.0;
    gridHelper.material.transparent = true;
    gridHelper.material.opacity = 0.25;
    this.scene.add(gridHelper);
  }

  bindEvents() {
    // Canvas Mouse Down / Move / Up for Rotation
    this.canvas.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.previousMousePosition = { x: e.clientX, y: e.clientY };
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      this.mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      if (this.isDragging) {
        const deltaX = e.clientX - this.previousMousePosition.x;
        const deltaY = e.clientY - this.previousMousePosition.y;

        this.monumentGroup.rotation.y += deltaX * 0.006;
        this.monumentGroup.rotation.x += deltaY * 0.006;

        this.previousMousePosition = { x: e.clientX, y: e.clientY };
      }
    });

    // Department Node Click to focus
    this.canvas.addEventListener('click', () => {
      if (this.hoveredNode) {
        const hud = document.getElementById('monument-hud-info');
        if (hud) {
          hud.innerHTML = `<strong>${this.hoveredNode.data.name}</strong><br><span>${this.hoveredNode.data.stats}</span>`;
        }
      }
    });

    window.addEventListener('resize', this.onResize.bind(this));
  }

  onResize() {
    if (!this.canvas) return;
    const width = this.canvas.clientWidth;
    const height = this.canvas.clientHeight;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }

  animate() {
    this.animationFrameId = requestAnimationFrame(this.animate.bind(this));

    const delta = this.clock.getDelta();
    const time = this.clock.getElapsedTime();

    // 1. Idle Monument Rotation (when not manually dragged)
    if (!this.isDragging && this.monumentGroup) {
      this.monumentGroup.rotation.y += 0.2 * delta;
    }

    // 2. Gyroscope Energy Rings Independent Rotation
    if (this.energyRings.length === 3) {
      this.energyRings[0].rotation.z += 0.4 * delta;
      this.energyRings[1].rotation.x += 0.3 * delta;
      this.energyRings[2].rotation.y -= 0.35 * delta;
    }

    // 3. Core Counter-Spin
    if (this.innerCore) {
      this.innerCore.rotation.y -= 0.5 * delta;
      this.innerCore.rotation.x += 0.2 * delta;
    }

    // 4. Department Nodes Oscillation & Facing Camera
    for (const node of this.departmentNodes) {
      const mesh = node.userData.mesh;
      const ring = node.userData.ring;

      mesh.rotation.y += 1.0 * delta;
      mesh.rotation.x += 0.5 * delta;
      ring.rotation.z += 0.8 * delta;

      // Bobbing
      node.position.y += Math.sin(time * 2 + node.position.x) * 0.002;
    }

    // 5. Raycasting for Node Hover
    this.raycaster.setFromCamera(this.mouse, this.camera);
    const interactiveMeshes = this.departmentNodes.map(n => n.userData.mesh);
    const intersects = this.raycaster.intersectObjects(interactiveMeshes);

    if (intersects.length > 0) {
      const hitMesh = intersects[0].object;
      const hitNode = this.departmentNodes.find(n => n.userData.mesh === hitMesh);

      if (hitNode) {
        this.hoveredNode = hitNode.userData;
        hitMesh.scale.set(1.4, 1.4, 1.4);
        this.canvas.style.cursor = 'pointer';

        // Update HUD
        const hud = document.getElementById('monument-hud-info');
        if (hud) {
          hud.innerHTML = `<span style="color:#00F5D4">${hitNode.userData.data.icon} ${hitNode.userData.data.name}</span><br><span style="color:#94A3B8">${hitNode.userData.data.stats}</span>`;
        }
      }
    } else {
      if (this.hoveredNode) {
        // Reset scale
        for (const n of this.departmentNodes) {
          n.userData.mesh.scale.set(1, 1, 1);
        }
        this.hoveredNode = null;
        this.canvas.style.cursor = 'default';
      }
    }

    this.renderer.render(this.scene, this.camera);
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    window.removeEventListener('resize', this.onResize);
    if (this.renderer) {
      this.renderer.dispose();
    }
  }
}

// Export for browser global scope
window.ApexPortal3D = ApexPortal3D;





