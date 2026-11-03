// Renders openvex.html: the list of published OpenVEX documents (vex/*.json,
// listed by Jekyll in the data-files attribute) and, with ?file=<name>, one
// document as a statements table (view=formatted) or pretty-printed JSON
// (view=raw).

(function () {
    "use strict";

    var STATUSES = ["affected", "under_investigation", "fixed", "not_affected"];

    function escapeHtml(text) {
        return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
            return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
        });
    }

    // Escapes text and renders `code` spans, which VEX statements use for
    // file and symbol names.
    function formatText(text) {
        return escapeHtml(text).replace(/`([^`]+)`/g, "<code>$1</code>");
    }

    function humanize(value) {
        var text = String(value || "").replace(/_/g, " ");
        return text.charAt(0).toUpperCase() + text.slice(1);
    }

    function formatDate(value) {
        return value
            ? String(value)
                  .replace("T", " ")
                  .replace(/:\d\d(\.\d+)?Z$/, " UTC")
            : "–";
    }

    function fetchText(url) {
        return fetch(url, {cache: "no-cache"}).then(function (r) {
            if (!r.ok) throw new Error(url + ": HTTP " + r.status);
            return r.text();
        });
    }

    // "percona-server-mongodb-8.3.11-3.vex.json" -> "8.3.11-3"
    function releaseOf(name) {
        var m = /^percona-server-mongodb-(.+?)\.(?:open)?vex\.json$/.exec(name);
        return m ? m[1] : null;
    }

    function compareReleases(a, b) {
        var ra = releaseOf(a) || "";
        var rb = releaseOf(b) || "";
        if (!ra || !rb) return ra ? -1 : rb ? 1 : a.localeCompare(b);
        var pa = ra.split(/[.-]/).map(Number);
        var pb = rb.split(/[.-]/).map(Number);
        for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
            if ((pa[i] || 0) !== (pb[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
        }
        return a.localeCompare(b);
    }

    function statusChip(status) {
        return (
            '<span class="sev-badge vex-' +
            escapeHtml(status) +
            '">' +
            escapeHtml(humanize(status)) +
            "</span>"
        );
    }

    function vulnerabilityUrl(vuln) {
        var name = vuln.name || "";
        if (/^CVE-\d+-\d+$/.test(name)) return "https://nvd.nist.gov/vuln/detail/" + name;
        if (/^GHSA-/.test(name)) return "https://github.com/advisories/" + name;
        return /^https?:\/\//.test(vuln["@id"] || "") ? vuln["@id"] : null;
    }

    function countStatuses(doc) {
        var counts = {};
        (doc.statements || []).forEach(function (s) {
            counts[s.status] = (counts[s.status] || 0) + 1;
        });
        return counts;
    }

    function statusOrder(counts) {
        return STATUSES.filter(function (s) {
            return counts[s];
        }).concat(
            Object.keys(counts).filter(function (s) {
                return STATUSES.indexOf(s) < 0;
            }),
        );
    }

    function renderList(root, base, files) {
        document.getElementById("vex-list").hidden = false;
        var tbody = root.querySelector("#vex-list tbody");
        var meta = document.getElementById("vex-list-meta");
        if (!files.length) {
            meta.textContent = "No OpenVEX documents are published yet.";
            return;
        }
        meta.textContent = files.length + " document" + (files.length === 1 ? "" : "s");
        tbody.innerHTML = files
            .map(function (name, i) {
                return (
                    '<tr data-row="' + i + '"><td colspan="6">' + escapeHtml(name) + "</td></tr>"
                );
            })
            .join("");

        files.forEach(function (name, i) {
            var row = tbody.querySelector('tr[data-row="' + i + '"]');
            var viewUrl = base + "/openvex.html?file=" + encodeURIComponent(name);
            var rawUrl = base + "/vex/" + encodeURIComponent(name);
            var release = releaseOf(name);
            var label =
                '<a class="cve-release" href="' +
                viewUrl +
                '">' +
                escapeHtml(release || name) +
                "</a>" +
                (release ? '<br><span class="cve-novex">' + escapeHtml(name) + "</span>" : "");
            fetchText(rawUrl)
                .then(JSON.parse)
                .then(function (doc) {
                    var counts = countStatuses(doc);
                    row.innerHTML =
                        "<td>" +
                        label +
                        '</td><td class="num">' +
                        (doc.statements || []).length +
                        '</td><td class="vex-statuses">' +
                        statusOrder(counts)
                            .map(function (s) {
                                return statusChip(s) + " " + counts[s];
                            })
                            .join(" ") +
                        '</td><td class="vex-date">' +
                        escapeHtml(formatDate(doc.last_updated || doc.timestamp)) +
                        "</td><td>" +
                        escapeHtml(doc.version == null ? "–" : doc.version) +
                        '</td><td class="vex-links"><a href="' +
                        viewUrl +
                        '">View</a> · <a href="' +
                        rawUrl +
                        '">Raw</a></td>';
                })
                .catch(function (err) {
                    row.innerHTML =
                        "<td>" +
                        label +
                        '</td><td colspan="4" class="cve-unscanned">Cannot load: ' +
                        escapeHtml(err.message) +
                        '</td><td class="vex-links"><a href="' +
                        rawUrl +
                        '">Raw</a></td>';
                });
        });
    }

    function renderProducts(products) {
        return (products || [])
            .map(function (p) {
                var subs = (p.subcomponents || [])
                    .map(function (s) {
                        return '<br><span class="vex-sub">↳ ' + escapeHtml(s["@id"]) + "</span>";
                    })
                    .join("");
                return '<span class="vex-product">' + escapeHtml(p["@id"]) + "</span>" + subs;
            })
            .join("<br>");
    }

    function renderStatement(s) {
        var parts = [];
        if (s.justification) {
            parts.push(
                '<span class="vex-label">' + escapeHtml(humanize(s.justification)) + "</span>",
            );
        }
        if (s.impact_statement) parts.push(formatText(s.impact_statement));
        if (s.action_statement) {
            parts.push('<span class="vex-label">Action:</span> ' + formatText(s.action_statement));
        }
        if (s.status_notes) parts.push(formatText(s.status_notes));
        return parts.join("<br>") || "–";
    }

    // Pretty-prints JSON with spans for keys, strings, numbers and literals.
    function highlightJson(text) {
        var json = JSON.stringify(JSON.parse(text), null, 2);
        var re =
            /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
        var out = "";
        var last = 0;
        var m;
        while ((m = re.exec(json))) {
            out += escapeHtml(json.slice(last, m.index));
            var cls = m[1]
                ? m[2]
                    ? "json-key"
                    : "json-string"
                : m[3]
                  ? "json-literal"
                  : "json-number";
            out +=
                '<span class="' +
                cls +
                '">' +
                escapeHtml(m[1] || m[0]) +
                "</span>" +
                escapeHtml(m[2] || "");
            last = re.lastIndex;
        }
        return out + escapeHtml(json.slice(last));
    }

    function renderDocument(root, base, name) {
        var params = new URLSearchParams(location.search);
        var rawUrl = base + "/vex/" + encodeURIComponent(name);
        var section = document.getElementById("vex-doc");
        var statusSelect = document.getElementById("vex-status");
        var search = document.getElementById("vex-search");
        var release = releaseOf(name);

        section.hidden = false;
        document.title = "OpenVEX " + (release || name) + " | Percona Server for MongoDB";
        document.getElementById("vex-title").textContent = release
            ? "OpenVEX for " + release
            : name;
        document.getElementById("vex-open-raw").href = rawUrl;
        var download = document.getElementById("vex-download");
        download.href = rawUrl;
        download.setAttribute("download", name);

        function updateUrl() {
            var p = new URLSearchParams();
            p.set("file", name);
            if (params.get("view") === "raw") p.set("view", "raw");
            if (statusSelect.value) p.set("status", statusSelect.value);
            if (search.value.trim()) p.set("q", search.value.trim());
            history.replaceState(null, "", "?" + p.toString());
        }

        function showView(view) {
            params.set("view", view);
            section.querySelectorAll(".cve-tab").forEach(function (tab) {
                var active = tab.dataset.view === view;
                tab.classList.toggle("active", active);
                tab.setAttribute("aria-selected", active ? "true" : "false");
            });
            document.getElementById("vex-formatted").hidden = view !== "formatted";
            document.getElementById("vex-raw").hidden = view !== "raw";
            updateUrl();
        }

        section.querySelectorAll(".cve-tab").forEach(function (tab) {
            tab.addEventListener("click", function () {
                showView(tab.dataset.view);
            });
        });
        showView(params.get("view") === "raw" ? "raw" : "formatted");

        fetchText(rawUrl)
            .then(function (text) {
                var doc = JSON.parse(text);
                var statements = doc.statements || [];
                var counts = countStatuses(doc);

                document.getElementById("vex-doc-meta").innerHTML =
                    escapeHtml(name) +
                    (doc.author ? " · " + escapeHtml(doc.author) : "") +
                    " · published " +
                    escapeHtml(formatDate(doc.timestamp)) +
                    (doc.last_updated
                        ? " · updated " + escapeHtml(formatDate(doc.last_updated))
                        : "") +
                    (doc.version != null ? " · version " + escapeHtml(doc.version) : "") +
                    (doc["@context"]
                        ? ' · <a href="' +
                          escapeHtml(doc["@context"]) +
                          '">' +
                          escapeHtml(doc["@context"].replace(/^https?:\/\//, "")) +
                          "</a>"
                        : "");

                statusOrder(counts).forEach(function (s) {
                    var option = document.createElement("option");
                    option.value = s;
                    option.textContent = humanize(s) + " (" + counts[s] + ")";
                    statusSelect.appendChild(option);
                });
                statusSelect.value = counts[params.get("status")] ? params.get("status") : "";
                search.value = params.get("q") || "";

                function renderStatements() {
                    var status = statusSelect.value;
                    var q = search.value.trim().toLowerCase();
                    var rows = statements
                        .filter(function (s) {
                            return (
                                (!status || s.status === status) &&
                                (!q || JSON.stringify(s).toLowerCase().indexOf(q) >= 0)
                            );
                        })
                        .sort(function (a, b) {
                            return (
                                STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status) ||
                                (a.vulnerability.name || "").localeCompare(
                                    b.vulnerability.name || "",
                                )
                            );
                        });
                    document.getElementById("vex-count").textContent =
                        rows.length + " of " + statements.length + " statements";
                    section.querySelector(".vex-statements tbody").innerHTML = rows.length
                        ? rows
                              .map(function (s) {
                                  var vuln = s.vulnerability || {};
                                  var url = vulnerabilityUrl(vuln);
                                  var id = escapeHtml(vuln.name || vuln["@id"] || "–");
                                  var aliases = (vuln.aliases || [])
                                      .map(function (a) {
                                          return (
                                              '<br><span class="cve-novex">' +
                                              escapeHtml(a) +
                                              "</span>"
                                          );
                                      })
                                      .join("");
                                  return (
                                      '<tr><td class="cve-id">' +
                                      (url
                                          ? '<a href="' + escapeHtml(url) + '">' + id + "</a>"
                                          : id) +
                                      aliases +
                                      "</td><td>" +
                                      statusChip(s.status) +
                                      '</td><td class="vex-products">' +
                                      renderProducts(s.products) +
                                      '</td><td class="cve-desc">' +
                                      renderStatement(s) +
                                      '</td><td class="vex-date">' +
                                      escapeHtml(formatDate(s.last_updated || s.timestamp)) +
                                      "</td></tr>"
                                  );
                              })
                              .join("")
                        : '<tr><td colspan="5" class="cve-unscanned">No statements match the filters.</td></tr>';
                    updateUrl();
                }

                statusSelect.addEventListener("change", renderStatements);
                search.addEventListener("input", renderStatements);
                renderStatements();

                document.getElementById("vex-json").innerHTML = highlightJson(text);
                var copy = document.getElementById("vex-copy");
                copy.addEventListener("click", function () {
                    navigator.clipboard.writeText(text).then(
                        function () {
                            copy.textContent = "Copied";
                            setTimeout(function () {
                                copy.textContent = "Copy JSON";
                            }, 1500);
                        },
                        function () {
                            copy.textContent = "Copy failed";
                        },
                    );
                });
            })
            .catch(function (err) {
                document.getElementById("vex-doc-meta").innerHTML =
                    '<span class="no-data-message">Cannot load ' +
                    escapeHtml(name) +
                    ": " +
                    escapeHtml(err.message) +
                    "</span>";
            });
    }

    var root = document.getElementById("openvex");
    if (!root) return;
    var base = root.dataset.base || "";
    var files = (root.dataset.files || "").split(/\s+/).filter(Boolean).sort(compareReleases);
    var file = new URLSearchParams(location.search).get("file");

    if (file && files.indexOf(file) >= 0) {
        document.getElementById("vex-list").hidden = true;
        renderDocument(root, base, file);
    } else {
        renderList(root, base, files);
    }
})();
