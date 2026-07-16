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
    }, { rootMargin: "0px 0px -8%", threshold: 0.12 });

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
      const original = button.textContent;

      try {
        await copyText(button.dataset.copy);
        button.textContent = "Copied";
        if (status) status.textContent = "Copied to the clipboard.";
      } catch {
        button.textContent = "Copy failed";
        if (status) status.textContent = "Clipboard access failed. Select and copy the command manually.";
      }

      window.setTimeout(() => {
        button.textContent = original;
      }, 1800);
    });
  });

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
      rule: "A beautiful still frame cannot prove a room configurator works at 60 frames per second."
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

  const tabs = [...document.querySelectorAll("[role='tab'][data-domain]")];
  const panel = document.getElementById("domain-panel");
  const fields = {
    code: document.getElementById("domain-code"),
    status: document.getElementById("domain-status"),
    title: document.getElementById("domain-title"),
    invariants: document.getElementById("domain-invariants"),
    medium: document.getElementById("domain-medium"),
    rule: document.getElementById("domain-rule")
  };

  const selectDomain = (tab, focus = false) => {
    const next = domainData[tab.dataset.domain];
    if (!next || !panel) return;

    tabs.forEach((item) => {
      const selected = item === tab;
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
    });

    panel.classList.add("switching");
    window.setTimeout(() => {
      Object.entries(fields).forEach(([key, element]) => {
        if (element) element.textContent = next[key];
      });
      panel.setAttribute("aria-labelledby", tab.id);
      panel.classList.remove("switching");
    }, reducedMotion ? 0 : 150);

    if (focus) tab.focus();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectDomain(tab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let nextIndex = index;
      if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
      if (event.key === "Home") nextIndex = 0;
      if (event.key === "End") nextIndex = tabs.length - 1;
      selectDomain(tabs[nextIndex], true);
    });
  });

  const evidenceFields = [...document.querySelectorAll("[data-evidence-key]")];
  if (evidenceFields.length) {
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
      })
      .catch(() => evidenceFields.forEach((element) => {
        element.textContent = "unverified";
      }));
  }
})();
