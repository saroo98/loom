document.documentElement.classList.add("js");

(() => {
  "use strict";

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const revealItems = [...document.querySelectorAll(".reveal")];

  if (reducedMotion || !("IntersectionObserver" in window)) {
    revealItems.forEach((item) => item.classList.add("is-visible"));
  } else {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -7%", threshold: 0.1 });

    revealItems.forEach((item) => observer.observe(item));
  }

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
      const statusId = button.getAttribute("aria-describedby");
      const status = statusId ? document.getElementById(statusId) : null;
      const originalLabel = button.textContent;

      try {
        await copyText(button.dataset.copy);
        button.textContent = "Copied";
        if (status) status.textContent = "Copied to the clipboard.";
      } catch {
        button.textContent = "Copy failed";
        if (status) status.textContent = "Clipboard access failed. Select and copy the command manually.";
      }

      window.setTimeout(() => {
        button.textContent = originalLabel;
      }, 1800);
    });
  });

  const bindTabs = (tabs, select) => {
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => select(tab));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();

        let nextIndex = index;
        if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        if (event.key === "Home") nextIndex = 0;
        if (event.key === "End") nextIndex = tabs.length - 1;
        select(tabs[nextIndex], true);
      });
    });
  };

  const requestData = {
    small: {
      prompt: "/loom Fix the CSV export header typo.",
      route: "TIER S",
      state: "READY",
      blocked: false,
      steps: [
        ["Current file state", "fingerprinted"],
        ["One compact work order", "bounded plan"],
        ["Targeted real check", "acceptance evidence"]
      ],
      output: "A small plan for a small change. No architecture ceremony."
    },
    system: {
      prompt: "/loom Migrate local authentication to passkeys.",
      route: "TIER L",
      state: "G1 REQUIRED",
      blocked: false,
      steps: [
        ["World and threat model", "current facts sealed"],
        ["Migration work graph", "dependencies + rollback"],
        ["Independent gate", "security and real-flow proof"]
      ],
      output: "Architecture, migration, security, testing, rollout, and recovery plans with atomic work orders."
    },
    unknown: {
      prompt: "/loom Plan a laboratory instrument calibration procedure.",
      route: "PROMOTED",
      state: "DISCOVERY BLOCK",
      blocked: true,
      steps: [
        ["Name the real domain", "generic defaults forbidden"],
        ["Find governing invariants", "authority + freshness"],
        ["Define the proof medium", "gate remains closed"]
      ],
      output: "No invented expertise. Loom discovers the affected rules before it authorizes a plan."
    }
  };

  const requestTabs = [...document.querySelectorAll("[role='tab'][data-request]")];
  const requestPanel = document.getElementById("request-panel");
  const requestFields = {
    prompt: document.getElementById("lab-prompt"),
    route: document.getElementById("lab-route"),
    state: document.getElementById("lab-state"),
    stepOne: document.getElementById("lab-step-one"),
    stepOneNote: document.getElementById("lab-step-one-note"),
    stepTwo: document.getElementById("lab-step-two"),
    stepTwoNote: document.getElementById("lab-step-two-note"),
    stepThree: document.getElementById("lab-step-three"),
    stepThreeNote: document.getElementById("lab-step-three-note"),
    output: document.getElementById("lab-output")
  };

  const selectRequest = (tab, focus = false) => {
    const next = requestData[tab.dataset.request];
    if (!next || !requestPanel) return;

    requestTabs.forEach((item) => {
      const selected = item === tab;
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
    });

    requestPanel.classList.add("switching");
    window.setTimeout(() => {
      requestFields.prompt.textContent = next.prompt;
      requestFields.route.textContent = next.route;
      requestFields.state.textContent = next.state;
      requestFields.state.classList.toggle("blocked", next.blocked);
      requestFields.stepOne.textContent = next.steps[0][0];
      requestFields.stepOneNote.textContent = next.steps[0][1];
      requestFields.stepTwo.textContent = next.steps[1][0];
      requestFields.stepTwoNote.textContent = next.steps[1][1];
      requestFields.stepThree.textContent = next.steps[2][0];
      requestFields.stepThreeNote.textContent = next.steps[2][1];
      requestFields.output.textContent = next.output;
      requestPanel.setAttribute("aria-labelledby", tab.id);
      requestPanel.classList.remove("switching");
    }, reducedMotion ? 0 : 130);

    if (focus) tab.focus();
  };

  bindTabs(requestTabs, selectRequest);

  const domainData = {
    accounting: {
      code: "DOMAIN / ACCOUNTING",
      status: "COVERAGE KNOWN",
      title: "Correct books before convenient screens.",
      invariants: "Balanced postings · currency precision · immutable audit trail · reconciliation · period close",
      medium: "Double-entry property tests · migration rehearsal · ledger reconciliation",
      rule: "A responsive dashboard cannot compensate for an unbalanced ledger."
    },
    "three-d": {
      code: "DOMAIN / REAL-TIME 3D",
      status: "COVERAGE KNOWN",
      title: "Spatial truth before visual spectacle.",
      invariants: "World units · coordinate systems · asset provenance · interaction states · frame-time budget",
      medium: "Target-device profiling · real asset pipeline · spatial interaction walkthrough",
      rule: "A beautiful still frame cannot prove a room configurator works at its frame-time target."
    },
    firmware: {
      code: "DOMAIN / FIRMWARE",
      status: "COVERAGE KNOWN",
      title: "Hardware constraints are part of the plan.",
      invariants: "Timing · memory limits · power states · interrupt safety · recovery path",
      medium: "Hardware-in-loop run · fault injection · power-cycle and rollback rehearsal",
      rule: "A unit test on a laptop cannot prove timing on the target device."
    },
    research: {
      code: "DOMAIN / RESEARCH",
      status: "COVERAGE KNOWN",
      title: "Uncertainty belongs in the deliverable.",
      invariants: "Question clarity · source quality · method · uncertainty · reproducibility",
      medium: "Source audit · independent method reproduction · claim-to-evidence trace",
      rule: "A polished conclusion cannot replace a reproducible method."
    },
    unknown: {
      code: "DOMAIN / UNCLASSIFIED",
      status: "DISCOVERY REQUIRED",
      title: "Loom says when it does not know.",
      invariants: "Failure modes unknown · governing rules unknown · proof medium unknown",
      medium: "Discover invariants and current facts before the execution gate can pass",
      rule: "Unknown coverage promotes the work and blocks authorization. Generic web defaults are forbidden."
    }
  };

  const domainTabs = [...document.querySelectorAll("[role='tab'][data-domain]")];
  const domainPanel = document.getElementById("domain-panel");
  const domainFields = {
    code: document.getElementById("domain-code"),
    status: document.getElementById("domain-status"),
    title: document.getElementById("domain-title"),
    invariants: document.getElementById("domain-invariants"),
    medium: document.getElementById("domain-medium"),
    rule: document.getElementById("domain-rule")
  };

  const selectDomain = (tab, focus = false) => {
    const next = domainData[tab.dataset.domain];
    if (!next || !domainPanel) return;

    domainTabs.forEach((item) => {
      const selected = item === tab;
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
    });

    domainPanel.classList.add("switching");
    window.setTimeout(() => {
      Object.entries(domainFields).forEach(([key, element]) => {
        if (element) element.textContent = next[key];
      });
      domainPanel.setAttribute("aria-labelledby", tab.id);
      domainPanel.classList.remove("switching");
    }, reducedMotion ? 0 : 130);

    if (focus) tab.focus();
  };

  bindTabs(domainTabs, selectDomain);

  const evidenceFields = [...document.querySelectorAll("[data-evidence-key]")];
  const versionFields = [...document.querySelectorAll("[data-loom-version]")];

  fetch("generated-evidence.json", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("evidence inventory unavailable");
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
      evidenceFields.forEach((element) => {
        element.textContent = "unverified";
      });
    });
})();
