document.documentElement.classList.add("js");

(() => {
  "use strict";

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const routeData = {
    small: {
      request: "Fix the CSV export header typo.",
      world: "Complete file state",
      domain: "Known local change",
      plan: "One work order",
      verify: "Targeted real check",
      learn: "Outcome, if useful",
      status: "EXAMPLE: READY FOR EXECUTION",
      detail: "SEALED / TIER S / ONE WORK ORDER",
      summary: "Illustrative route: small work stays small without skipping verification."
    },
    system: {
      request: "Migrate local authentication to passkeys.",
      world: "State + threat model",
      domain: "Security + migration",
      plan: "Dependency work graph",
      verify: "Real flow + rollback",
      learn: "Measured migration outcome",
      status: "EXAMPLE: G1 REVIEW REQUIRED",
      detail: "SEALED / TIER L / DEPENDENCY GRAPH",
      summary: "Illustrative route: consequential work earns deeper architecture, security, migration, and rollback planning."
    },
    unknown: {
      request: "Plan a laboratory instrument calibration procedure.",
      world: "Project state observed",
      domain: "Authority still unknown",
      plan: "Draft route only",
      verify: "Proof medium unknown",
      learn: "Nothing admitted yet",
      status: "EXAMPLE: DISCOVERY REQUIRED",
      detail: "BLOCKED / UNKNOWN DOMAIN / NO EXECUTION",
      summary: "Illustrative route: Loom names missing authority and proof instead of inventing domain expertise."
    }
  };

  const terrain = document.querySelector(".terrain");
  const routePanel = document.getElementById("route-story");
  const tabs = [...document.querySelectorAll("[role='tab'][data-route]")];
  const fields = {
    request: document.getElementById("map-request"),
    world: document.getElementById("label-world"),
    domain: document.getElementById("label-domain"),
    plan: document.getElementById("label-plan"),
    verify: document.getElementById("label-verify"),
    learn: document.getElementById("label-learn"),
    status: document.getElementById("seal-status"),
    detail: document.getElementById("seal-detail"),
    summary: document.getElementById("route-summary")
  };

  const restartRouteAnimation = () => {
    if (reducedMotion || !terrain) return;
    const network = terrain.querySelector(".route-active");
    if (!network) return;
    network.style.animation = "none";
    network.querySelectorAll("path").forEach((path) => {
      path.style.animation = "none";
      void path.getBoundingClientRect();
      path.style.animation = "";
    });
    network.style.animation = "";
  };

  const selectRoute = (tab, focus = false) => {
    const next = routeData[tab.dataset.route];
    if (!next || !terrain) return;

    tabs.forEach((item) => {
      const selected = item === tab;
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
    });

    terrain.dataset.routeMode = tab.dataset.route;
    if (routePanel) routePanel.setAttribute("aria-labelledby", tab.id);
    Object.entries(fields).forEach(([key, element]) => {
      if (element) element.textContent = next[key];
    });
    restartRouteAnimation();
    if (focus) tab.focus();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectRoute(tab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      selectRoute(tabs[next], true);
    });
  });

  const copyText = async (value) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    if (!copied) throw new Error("Clipboard unavailable");
  };

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const status = document.getElementById(button.getAttribute("aria-describedby"));
      const original = button.textContent;
      try {
        await copyText(button.dataset.copy);
        button.textContent = "Copied";
        if (status) status.textContent = "Request copied to the clipboard.";
      } catch {
        button.textContent = "Copy failed";
        if (status) status.textContent = "Clipboard access failed. Select and copy the request manually.";
      }
      window.setTimeout(() => { button.textContent = original; }, 1800);
    });
  });

  const evidenceFields = [...document.querySelectorAll("[data-evidence-key]")];
  const versionFields = [...document.querySelectorAll("[data-loom-version]")];

  fetch("generated-evidence.json", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("Evidence inventory unavailable");
      return response.json();
    })
    .then((evidence) => {
      evidenceFields.forEach((element) => {
        const value = evidence[element.dataset.evidenceKey];
        element.textContent = Number.isInteger(value) ? String(value) : "unverified";
      });
      if (typeof evidence.loom_version === "string") {
        versionFields.forEach((element) => {
          element.textContent = evidence.loom_version;
          element.dataset.loomVersion = evidence.loom_version;
        });
      }
    })
    .catch(() => {
      evidenceFields.forEach((element) => { element.textContent = "unverified"; });
    });
})();
