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

  createSignalField(document.querySelector("[data-signal-field]"));
  createSignalField(document.querySelector("[data-closing-field]"), true);
})();
