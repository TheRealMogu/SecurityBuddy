/* Progressive visual enhancements — lazy-loaded, never block first paint.
 *
 * Loaded with `defer` and activated only after window load + idle.
 * Every effect bails out gracefully: reduced-motion users, data-saver
 * connections and browsers without WebGL simply keep the static CSS look.
 *
 *  - Hero: animated shader gradient (ShaderGradient-style, zero deps)
 *  - Feature cards: cursor spotlight + staggered scroll reveal
 */
(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var saveData = !!(navigator.connection && navigator.connection.saveData);

  function onIdle(fn) {
    if ('requestIdleCallback' in window) {
      requestIdleCallback(fn, { timeout: 2000 });
    } else {
      setTimeout(fn, 200);
    }
  }

  function start() {
    onIdle(function () {
      if (!reduceMotion && !saveData) initHeroGradient();
      initCardSpotlight();
      if (!reduceMotion) initScrollReveal();
    });
  }

  if (document.readyState === 'complete') {
    start();
  } else {
    window.addEventListener('load', start);
  }

  /* ── Theme color helpers ─────────────────────────────────────────── */

  function cssColor(name) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    if (v[0] === '#') {
      if (v.length === 4) v = '#' + v[1] + v[1] + v[2] + v[2] + v[3] + v[3];
      return [
        parseInt(v.slice(1, 3), 16) / 255,
        parseInt(v.slice(3, 5), 16) / 255,
        parseInt(v.slice(5, 7), 16) / 255
      ];
    }
    var m = v.match(/[\d.]+/g);
    return m ? [m[0] / 255, m[1] / 255, m[2] / 255] : [0, 0, 0];
  }

  function mixColor(a, b, t) {
    return [
      a[0] + (b[0] - a[0]) * t,
      a[1] + (b[1] - a[1]) * t,
      a[2] + (b[2] - a[2]) * t
    ];
  }

  /* ── Hero shader gradient ────────────────────────────────────────── */

  // Every page's banner gets the gradient backdrop. We inject the host
  // element so no template needs editing — present and future pages with
  // a `.hero-section` or `.premium-hero` are covered automatically.
  function ensureHeroBg() {
    var existing = document.querySelector('.hero-bg');
    if (existing) return existing;
    var section = document.querySelector('.hero-section, .premium-hero');
    if (!section) return null;
    var bg = document.createElement('div');
    bg.className = 'hero-bg';
    bg.setAttribute('aria-hidden', 'true');
    section.insertBefore(bg, section.firstChild);
    return bg;
  }

  var VERT =
    'attribute vec2 a_pos;' +
    'void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }';

  // 2D simplex noise: Ian McEwan / Ashima Arts (MIT), webgl-noise
  var FRAG = [
    'precision mediump float;',
    'uniform float u_time;',
    'uniform vec2 u_res;',
    'uniform vec3 u_c1;', // page background
    'uniform vec3 u_c2;', // primary tint
    'uniform vec3 u_c3;', // secondary tint
    'vec3 permute(vec3 x) { return mod(((x*34.0)+1.0)*x, 289.0); }',
    'float snoise(vec2 v) {',
    '  const vec4 C = vec4(0.211324865405187, 0.366025403784439, -0.577350269189626, 0.024390243902439);',
    '  vec2 i  = floor(v + dot(v, C.yy));',
    '  vec2 x0 = v - i + dot(i, C.xx);',
    '  vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);',
    '  vec4 x12 = x0.xyxy + C.xxzz;',
    '  x12.xy -= i1;',
    '  i = mod(i, 289.0);',
    '  vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0)) + i.x + vec3(0.0, i1.x, 1.0));',
    '  vec3 m = max(0.5 - vec3(dot(x0,x0), dot(x12.xy,x12.xy), dot(x12.zw,x12.zw)), 0.0);',
    '  m = m*m; m = m*m;',
    '  vec3 x = 2.0 * fract(p * C.www) - 1.0;',
    '  vec3 h = abs(x) - 0.5;',
    '  vec3 ox = floor(x + 0.5);',
    '  vec3 a0 = x - ox;',
    '  m *= 1.79284291400159 - 0.85373472095314 * (a0*a0 + h*h);',
    '  vec3 g;',
    '  g.x = a0.x * x0.x + h.x * x0.y;',
    '  g.yz = a0.yz * x12.xz + h.yz * x12.yw;',
    '  return 130.0 * dot(m, g);',
    '}',
    'void main() {',
    '  vec2 uv = gl_FragCoord.xy / u_res;',
    '  vec2 p = vec2(uv.x * u_res.x / u_res.y, uv.y);',
    '  float t = u_time * 0.05;',
    '  float n1 = snoise(p * 0.9 + vec2(t, -t * 0.6));',
    '  float n2 = snoise(p * 1.6 + vec2(-t * 0.7, t * 0.4) + 7.3);',
    '  vec3 col = u_c1;',
    '  col = mix(col, u_c2, smoothstep(0.1, 1.0, n1) * 0.85);',
    '  col = mix(col, u_c3, smoothstep(0.3, 1.0, n2) * 0.6);',
    // blend into the page background towards the bottom edge of the hero
    '  col = mix(u_c1, col, smoothstep(0.05, 0.55, uv.y));',
    '  gl_FragColor = vec4(col, 1.0);',
    '}'
  ].join('\n');

  function initHeroGradient() {
    var host = ensureHeroBg();
    if (!host) return;

    var canvas = document.createElement('canvas');
    var gl = canvas.getContext('webgl', { alpha: false, antialias: false, powerPreference: 'low-power' }) ||
             canvas.getContext('experimental-webgl', { alpha: false });
    if (!gl) return;

    function compile(type, src) {
      var s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
    }

    var vs = compile(gl.VERTEX_SHADER, VERT);
    var fs = compile(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;

    var prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);

    // single fullscreen triangle
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    var aPos = gl.getAttribLocation(prog, 'a_pos');
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    var uTime = gl.getUniformLocation(prog, 'u_time');
    var uRes = gl.getUniformLocation(prog, 'u_res');
    var uC1 = gl.getUniformLocation(prog, 'u_c1');
    var uC2 = gl.getUniformLocation(prog, 'u_c2');
    var uC3 = gl.getUniformLocation(prog, 'u_c3');

    function setColors() {
      var bg = cssColor('--color-bg');
      var primary = cssColor('--color-primary');
      var info = cssColor('--color-info');
      gl.uniform3fv(uC1, new Float32Array(bg));
      gl.uniform3fv(uC2, new Float32Array(mixColor(bg, primary, 0.4)));
      gl.uniform3fv(uC3, new Float32Array(mixColor(bg, info, 0.3)));
    }

    function resize() {
      var dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.max(1, Math.round(host.clientWidth * dpr));
      canvas.height = Math.max(1, Math.round(host.clientHeight * dpr));
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(uRes, canvas.width, canvas.height);
    }

    var inView = true;
    var pageVisible = !document.hidden;
    var lost = false;
    var raf = null;
    var t0 = performance.now();

    function frame(now) {
      raf = null;
      gl.uniform1f(uTime, (now - t0) / 1000);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      schedule();
    }

    function schedule() {
      if (inView && pageVisible && !lost && raf === null) {
        raf = requestAnimationFrame(frame);
      }
    }

    canvas.addEventListener('webglcontextlost', function (e) {
      e.preventDefault();
      lost = true;
      canvas.classList.remove('is-ready');
    });

    document.addEventListener('visibilitychange', function () {
      pageVisible = !document.hidden;
      schedule();
    });

    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (entries) {
        inView = entries[entries.length - 1].isIntersecting;
        schedule();
      }).observe(host);
    }

    // follow the light/dark toggle in base.html
    new MutationObserver(setColors).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });

    var resizeTimer = null;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(resize, 150);
    });

    host.appendChild(canvas);
    resize();
    setColors();
    schedule();
    requestAnimationFrame(function () { canvas.classList.add('is-ready'); });
  }

  /* ── Feature cards: cursor spotlight ─────────────────────────────── */

  function initCardSpotlight() {
    if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;
    var grid = document.querySelector('.features-grid');
    if (!grid) return;

    grid.classList.add('js-spotlight');
    grid.addEventListener('mousemove', function (e) {
      var card = e.target.closest && e.target.closest('.feature-card');
      if (!card) return;
      var r = card.getBoundingClientRect();
      card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      card.style.setProperty('--my', (e.clientY - r.top) + 'px');
    });
  }

  /* ── Feature cards: staggered scroll reveal ──────────────────────── */

  function initScrollReveal() {
    if (!('IntersectionObserver' in window)) return;
    var cards = document.querySelectorAll('.features-grid .feature-card');
    if (!cards.length) return;

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -8% 0px' });

    var fold = window.innerHeight;
    var queued = 0;
    cards.forEach(function (card) {
      // cards already on screen stay put — hiding them now would flash
      if (card.getBoundingClientRect().top < fold) return;
      card.classList.add('will-reveal');
      card.style.transitionDelay = (queued % 3) * 70 + 'ms';
      queued++;
      io.observe(card);
    });
  }
})();
