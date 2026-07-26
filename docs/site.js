(() => {
  "use strict";

  const installTarget = "#install";

  const prepareHeroAction = () => {
    const heroButton = document.querySelector("#root button");
    if (!heroButton) {
      return false;
    }
    heroButton.type = "button";
    heroButton.setAttribute("aria-label", "Jump to the Loom installation command");
    heroButton.addEventListener("click", () => {
      document.querySelector(installTarget)?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto"
          : "smooth",
        block: "center",
      });
    });
    return true;
  };

  if (!prepareHeroAction()) {
    const observer = new MutationObserver(() => {
      if (prepareHeroAction()) {
        observer.disconnect();
      }
    });
    observer.observe(document.getElementById("root"), {
      childList: true,
      subtree: true,
    });
  }

  document.querySelectorAll('a[href^="https://"]').forEach((link) => {
    link.rel = "noopener";
  });

  const copyButton = document.querySelector("[data-copy-install]");
  const copyLabel = document.querySelector("[data-copy-label]");
  const copyStatus = document.querySelector("[data-copy-status]");
  let resetCopyState;

  const fallbackCopy = (value) => {
    const field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    if (!copied) {
      throw new Error("Copy command was rejected");
    }
  };

  copyButton?.addEventListener("click", async () => {
    const command = copyButton.dataset.command;
    if (!command) {
      return;
    }

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(command);
      } else {
        fallbackCopy(command);
      }
      window.clearTimeout(resetCopyState);
      copyButton.classList.add("is-copied");
      copyButton.setAttribute("aria-label", "Loom installation command copied");
      copyLabel.textContent = "Copied";
      copyStatus.textContent = "Loom installation command copied to the clipboard.";
      resetCopyState = window.setTimeout(() => {
        copyButton.classList.remove("is-copied");
        copyButton.setAttribute(
          "aria-label",
          "Copy the Loom global installation command"
        );
        copyLabel.textContent = "Copy";
      }, 2400);
    } catch {
      copyStatus.textContent =
        "Copy was unavailable. Select the command and copy it manually.";
    }
  });
})();
