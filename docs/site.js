(() => {
  "use strict";

  const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  let reducedMotion = motionQuery.matches;
  const clamp = (value, minimum, maximum) => Math.min(maximum, Math.max(minimum, value));

  const header = document.querySelector("[data-header]");
  const copyButton = document.querySelector("[data-copy-button]");
  const copyValue = document.querySelector("[data-copy-value]");
  const copyLabel = document.querySelector("[data-copy-label]");
  const copyToast = document.querySelector("[data-copy-toast]");

  const updateHeader = () => {
    if (header) header.classList.toggle("is-scrolled", window.scrollY > 24);
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
          copyToast.textContent = "Loom request copied.";
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
          copyToast.textContent = "Request selected. Press Ctrl+C or Command+C.";
          copyToast.classList.add("is-visible");
        }
      }
    });
  }

  const sourceVisualShell = document.querySelector("[data-source-visual-shell]");
  const sourceVisualFrame = document.querySelector("[data-source-visual]");

  const prepareSourceVisual = () => {
    if (!sourceVisualFrame || !sourceVisualShell) return;

    sourceVisualShell.classList.add("is-ready");

    try {
      sourceVisualFrame.contentWindow?.scrollTo(0, 0);
    } catch {
      // The embedded renderer is self-contained and remains usable without frame access.
    }
  };

  if (sourceVisualFrame) {
    sourceVisualFrame.addEventListener("load", prepareSourceVisual);
  }

  window.addEventListener("message", (event) => {
    if (
      event.source === sourceVisualFrame?.contentWindow &&
      event.data?.type === "loom:visual-pointer-ack"
    ) {
      sourceVisualShell?.setAttribute("data-pointer-bridge", "active");
    }
  });

  let pendingVisualPointer = null;
  let visualPointerFrameRequested = false;

  const sendPointerToSource = () => {
    visualPointerFrameRequested = false;
    if (reducedMotion || !pendingVisualPointer) {
      pendingVisualPointer = null;
      return;
    }

    sourceVisualFrame.contentWindow?.postMessage(pendingVisualPointer, "*");
    pendingVisualPointer = null;
  };

  const forwardPointerToSource = (event) => {
    if (reducedMotion || !sourceVisualShell?.classList.contains("is-ready")) return;

    pendingVisualPointer = {
      type: "loom:visual-pointer",
      clientX: event.clientX,
      clientY: event.clientY,
      pointerType: event.pointerType
    };

    if (!visualPointerFrameRequested) {
      visualPointerFrameRequested = true;
      window.requestAnimationFrame(sendPointerToSource);
    }
  };

  window.addEventListener("pointermove", forwardPointerToSource, { passive: true });

  const story = document.querySelector("[data-story]");
  const storySteps = [...document.querySelectorAll("[data-story-step]")];
  const storyProgress = document.querySelector("[data-story-progress]");
  let storyFrameRequested = false;
  let currentStoryIndex = -1;

  const updateStory = () => {
    if (!story || !storySteps.length) return;
    const viewportAnchor = window.innerHeight * 0.53;
    let closestIndex = 0;
    let closestDistance = Number.POSITIVE_INFINITY;

    storySteps.forEach((step, index) => {
      const rect = step.getBoundingClientRect();
      const center = rect.top + rect.height / 2;
      const distance = Math.abs(center - viewportAnchor);
      if (distance < closestDistance) {
        closestDistance = distance;
        closestIndex = index;
      }
    });

    if (closestIndex !== currentStoryIndex) {
      currentStoryIndex = closestIndex;
      storySteps.forEach((step, index) => step.classList.toggle("is-current", index === closestIndex));
    }

    if (storyProgress) {
      const rect = story.getBoundingClientRect();
      const range = Math.max(1, rect.height - window.innerHeight);
      const progress = clamp(-rect.top / range, 0, 1);
      storyProgress.style.transform = `scaleY(${progress})`;
    }
    storyFrameRequested = false;
  };

  const requestStoryUpdate = () => {
    if (storyFrameRequested) return;
    storyFrameRequested = true;
    window.requestAnimationFrame(updateStory);
  };

  if (storySteps.length) {
    window.addEventListener("scroll", requestStoryUpdate, { passive: true });
    window.addEventListener("resize", requestStoryUpdate, { passive: true });
    updateStory();
  }

  const handleMotionChange = (event) => {
    reducedMotion = event.matches;
  };

  if (typeof motionQuery.addEventListener === "function") {
    motionQuery.addEventListener("change", handleMotionChange);
  } else if (typeof motionQuery.addListener === "function") {
    motionQuery.addListener(handleMotionChange);
  }
})();
