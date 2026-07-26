(() => {
  "use strict";

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const header = document.querySelector("[data-header]");
  const copyButton = document.querySelector("[data-copy-button]");
  const copyValue = document.querySelector("[data-copy-value]");
  const copyLabel = document.querySelector("[data-copy-label]");
  const copyToast = document.querySelector("[data-copy-toast]");

  const updateHeader = () => {
    if (!header) return;
    header.classList.toggle("is-scrolled", window.scrollY > 24);
  };

  updateHeader();
  window.addEventListener("scroll", updateHeader, { passive: true });

  if (copyButton && copyValue) {
    copyButton.addEventListener("click", async () => {
      const text = copyValue.textContent.trim();
      try {
        await navigator.clipboard.writeText(text);
        if (copyLabel) copyLabel.textContent = "Copied";
        if (copyToast) {
          copyToast.textContent = "Marketplace command copied.";
          copyToast.classList.add("is-visible");
        }
        window.setTimeout(() => {
          if (copyLabel) copyLabel.textContent = "Copy";
          if (copyToast) copyToast.classList.remove("is-visible");
        }, 1800);
      } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(copyValue);
        selection.removeAllRanges();
        selection.addRange(range);
        if (copyToast) {
          copyToast.textContent = "Command selected. Press Ctrl+C or Command+C.";
          copyToast.classList.add("is-visible");
        }
      }
    });
  }

  const createLoomParticleField = (canvas) => {
    if (!canvas) return;

    const context = canvas.getContext("2d", { alpha: true });
    if (!context) return;

    const smoothstep = (start, end, value) => {
      const amount = Math.min(1, Math.max(0, (value - start) / (end - start)));
      return amount * amount * (3 - 2 * amount);
    };

    let width = 0;
    let height = 0;
    let particles = [];
    let animationFrame = 0;
    let visible = true;
    let pointer = { x: -1000, y: -1000, active: false };

    const buildParticles = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);

      const sampleCanvas = document.createElement("canvas");
      const sampleContext = sampleCanvas.getContext("2d", { willReadFrequently: true });
      if (!sampleContext) return;

      sampleCanvas.width = Math.max(320, Math.round(width));
      sampleCanvas.height = Math.max(180, Math.round(height * 0.44));
      const fontSize = Math.min(width * 0.215, sampleCanvas.height * 0.74);
      sampleContext.clearRect(0, 0, sampleCanvas.width, sampleCanvas.height);
      sampleContext.fillStyle = "#fff";
      sampleContext.font = `900 ${fontSize}px Arial Black, Arial, sans-serif`;
      sampleContext.textAlign = "center";
      sampleContext.textBaseline = "middle";
      sampleContext.fillText("LOOM", sampleCanvas.width / 2, sampleCanvas.height / 2);

      const pixels = sampleContext.getImageData(
        0,
        0,
        sampleCanvas.width,
        sampleCanvas.height
      ).data;
      const step = width < 680 ? 5 : width < 1200 ? 4 : 3;
      const nextParticles = [];
      const yOffset = Math.max(72, height * 0.075);

      for (let y = 0; y < sampleCanvas.height; y += step) {
        for (let x = 0; x < sampleCanvas.width; x += step) {
          if (pixels[(y * sampleCanvas.width + x) * 4 + 3] < 150) continue;
          const angle = ((x * 0.37 + y * 0.19) % 6.283) - 3.1415;
          const distance = 60 + ((x * 17 + y * 13) % Math.max(90, width * 0.42));
          const homeX = x;
          const homeY = y + yOffset;
          nextParticles.push({
            homeX,
            homeY,
            x: width / 2 + Math.cos(angle) * distance,
            y: homeY + Math.sin(angle) * distance * 0.42,
            scatterX: width / 2 + Math.cos(angle) * distance,
            scatterY: homeY + Math.sin(angle) * distance * 0.42,
            phase: (x * 0.071 + y * 0.113) % 6.283,
            radius: 0.78 + ((x + y) % 5) * 0.18
          });
        }
      }

      const maximum = width < 680 ? 1900 : 4800;
      const stride = Math.max(1, Math.ceil(nextParticles.length / maximum));
      particles = nextParticles.filter((_, index) => index % stride === 0);
    };

    const draw = (time = 0) => {
      context.clearRect(0, 0, width, height);
      const cycle = reducedMotion ? 0.34 : (time % 12000) / 12000;
      const forming = smoothstep(0.02, 0.18, cycle);
      const dissolving = smoothstep(0.7, 0.86, cycle);
      const formation = reducedMotion ? 1 : forming * (1 - dissolving);
      const drift = time * 0.00032;

      for (const particle of particles) {
        const noiseX = Math.cos(drift + particle.phase) * 7;
        const noiseY = Math.sin(drift * 0.84 + particle.phase) * 5;
        let targetX = particle.scatterX + noiseX;
        let targetY = particle.scatterY + noiseY;
        targetX += (particle.homeX - targetX) * formation;
        targetY += (particle.homeY - targetY) * formation;

        if (pointer.active) {
          const dx = targetX - pointer.x;
          const dy = targetY - pointer.y;
          const distanceSquared = dx * dx + dy * dy;
          if (distanceSquared < 7000 && distanceSquared > 0) {
            const force = (1 - distanceSquared / 7000) * 34;
            const distance = Math.sqrt(distanceSquared);
            targetX += (dx / distance) * force;
            targetY += (dy / distance) * force;
          }
        }

        particle.x += (targetX - particle.x) * (reducedMotion ? 1 : 0.085);
        particle.y += (targetY - particle.y) * (reducedMotion ? 1 : 0.085);
        const alpha = 0.36 + formation * 0.58;
        context.fillStyle = `rgba(255,255,255,${alpha})`;
        context.fillRect(particle.x, particle.y, particle.radius, particle.radius);
      }

      if (!reducedMotion && visible && !document.hidden) {
        animationFrame = window.requestAnimationFrame(draw);
      }
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      if (visible && !document.hidden) animationFrame = window.requestAnimationFrame(draw);
    };

    const updatePointer = (event) => {
      const rect = canvas.getBoundingClientRect();
      pointer = {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        active: true
      };
    };

    const clearPointer = () => {
      pointer.active = false;
    };

    const resize = () => {
      buildParticles();
      draw(reducedMotion ? 4000 : performance.now());
      restart();
    };

    const observer =
      "IntersectionObserver" in window
        ? new IntersectionObserver(([entry]) => {
            visible = entry.isIntersecting;
            if (visible) restart();
            else window.cancelAnimationFrame(animationFrame);
          })
        : null;

    buildParticles();
    draw(reducedMotion ? 4000 : performance.now());
    restart();
    observer?.observe(canvas);
    window.addEventListener("resize", resize, { passive: true });
    document.addEventListener("visibilitychange", restart);
    canvas.addEventListener("pointermove", updatePointer, { passive: true });
    canvas.addEventListener("pointerleave", clearPointer, { passive: true });
  };

  const createSignalField = (canvas, compact = false) => {
    if (!canvas) return;

    const context = canvas.getContext("2d", { alpha: true });
    if (!context) return;

    let width = 0;
    let height = 0;
    let animationFrame = 0;
    let points = [];
    let pointerX = 0.7;
    let pointerY = 0.45;

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);

      const density = compact ? 28 : Math.min(72, Math.max(38, Math.round(width / 22)));
      points = Array.from({ length: density }, (_, index) => ({
        phase: index * 0.37,
        offset: ((index * 73) % 101) / 101,
        weight: 0.3 + ((index * 29) % 70) / 100
      }));
    };

    const draw = (time = 0) => {
      context.clearRect(0, 0, width, height);
      const elapsed = time * 0.00022;

      context.lineWidth = 0.65;
      for (let index = 0; index < points.length; index += 1) {
        const point = points[index];
        const yBase = height * (0.12 + point.offset * 0.76);
        const influenceY = (pointerY - 0.5) * height * 0.1;
        const amplitude = (compact ? 18 : 34) + point.weight * 44;

        context.beginPath();
        for (let step = 0; step <= 48; step += 1) {
          const x = (step / 48) * width;
          const normalizedX = x / width;
          const pointerPull = Math.exp(-Math.pow(normalizedX - pointerX, 2) / 0.028);
          const y =
            yBase +
            Math.sin(normalizedX * 8.5 + elapsed + point.phase) * amplitude +
            Math.cos(normalizedX * 3.8 - elapsed * 0.7 + point.phase) * amplitude * 0.35 +
            pointerPull * influenceY;
          if (step === 0) context.moveTo(x, y);
          else context.lineTo(x, y);
        }
        const alpha = 0.045 + point.weight * 0.095;
        context.strokeStyle = `rgba(255,255,255,${alpha})`;
        context.stroke();
      }

      if (!reducedMotion) {
        animationFrame = window.requestAnimationFrame(draw);
      }
    };

    const updatePointer = (event) => {
      const rect = canvas.getBoundingClientRect();
      pointerX = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
      pointerY = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
    };

    resize();
    draw();
    window.addEventListener("resize", resize, { passive: true });
    canvas.addEventListener("pointermove", updatePointer, { passive: true });

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
      canvas.removeEventListener("pointermove", updatePointer);
    };
  };

  createLoomParticleField(document.querySelector("[data-loom-particle-field]"));
  createSignalField(document.querySelector("[data-closing-field]"), true);
})();
