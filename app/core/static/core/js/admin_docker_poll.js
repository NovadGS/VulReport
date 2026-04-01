(function () {
  const root = document.getElementById("docker-stats-root");
  if (!root) return;

  const url = root.dataset.url;
  const tbody = document.getElementById("docker-stats-tbody");
  const meta = document.getElementById("docker-stats-meta");
  const errBox = document.getElementById("docker-stats-error");

  function fmtPct(v) {
    if (v === null || v === undefined || Number.isNaN(v)) return "—";
    return v + " %";
  }

  function fmtMem(used, limit, pct) {
    if (used == null) return "—";
    const u = used + " Mo";
    if (limit == null) return u;
    return u + " / " + limit + " Mo (" + fmtPct(pct) + ")";
  }

  async function refresh() {
    try {
      const res = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
      const data = await res.json();
      if (!data.ok) {
        errBox.classList.remove("d-none");
        errBox.textContent = data.error || "Erreur inconnue.";
        tbody.innerHTML = "";
        meta.textContent = "";
        return;
      }
      errBox.classList.add("d-none");
      errBox.textContent = "";
      meta.textContent = data.docker_version ? "Docker " + data.docker_version + " — MAJ toutes les 3 s" : "MAJ toutes les 3 s";
      tbody.innerHTML = "";
      (data.containers || []).forEach(function (c) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td><code>" +
          (c.name || "") +
          "</code></td>" +
          "<td>" +
          (c.status || "") +
          "</td>" +
          "<td class=\"small text-truncate\" style=\"max-width:220px\" title=\"" +
          (c.image || "") +
          "\">" +
          (c.image || "") +
          "</td>" +
          "<td>" +
          fmtPct(c.cpu_percent) +
          "</td>" +
          "<td>" +
          fmtMem(c.mem_used_mb, c.mem_limit_mb, c.mem_percent) +
          "</td>";
        tbody.appendChild(tr);
      });
      if (!data.containers || !data.containers.length) {
        tbody.innerHTML = "<tr><td colspan=\"5\" class=\"text-muted\">Aucun conteneur.</td></tr>";
      }
    } catch (e) {
      errBox.classList.remove("d-none");
      errBox.textContent = "Impossible de charger les stats Docker (" + e + ").";
    }
  }

  refresh();
  setInterval(refresh, 3000);
})();
