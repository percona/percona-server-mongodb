/**
 * Dynamic PR Status for Fork Status Page
 * - Queries GitHub API to find PRs associated with commits
 * - Shows PR links (open/merged/closed) or "Create PR" button
 * - Caches results in sessionStorage (10 minute TTL)
 */
(function () {
  const CONFIG = {
    repoOwner: null,
    repoName: null,
    branchPrefix: "mergai/",
    cacheTTL: 10 * 60 * 1000, // 10 minutes
    cacheKey: "psmdb_pr_cache",
    maxPages: 3,
  };

  const PR_STATES = {
    open: { icon: "🔄", label: "Open PR", class: "pr-open" },
    merged: { icon: "✅", label: "Merged", class: "pr-merged" },
    closed: { icon: "❌", label: "Closed", class: "pr-closed" },
  };

  /**
   * Fetch PRs from GitHub API with pagination
   */
  async function fetchPullRequests() {
    const prs = [];
    let page = 1;
    const perPage = 100;

    while (page <= CONFIG.maxPages) {
      try {
        const response = await fetch(
          `https://api.github.com/repos/${CONFIG.repoOwner}/${CONFIG.repoName}/pulls?state=all&per_page=${perPage}&page=${page}`,
          { headers: { Accept: "application/vnd.github.v3+json" } },
        );

        if (!response.ok) {
          if (response.status === 403) {
            console.warn("GitHub API rate limit reached");
          }
          break;
        }

        const data = await response.json();
        if (data.length === 0) break;

        prs.push(
          ...data.map((pr) => ({
            number: pr.number,
            title: pr.title,
            html_url: pr.html_url,
            state: pr.state,
            merged_at: pr.merged_at,
            head_ref: pr.head.ref,
          })),
        );

        page++;
      } catch (error) {
        console.error("Error fetching PRs:", error);
        break;
      }
    }

    return prs;
  }

  /**
   * Get PRs with caching
   */
  async function fetchPRsWithCache() {
    const cached = sessionStorage.getItem(CONFIG.cacheKey);
    if (cached) {
      try {
        const { data, timestamp } = JSON.parse(cached);
        if (Date.now() - timestamp < CONFIG.cacheTTL) {
          console.log("PR status: using cached data");
          return data;
        }
      } catch (e) {
        sessionStorage.removeItem(CONFIG.cacheKey);
      }
    }

    console.log("PR status: fetching from GitHub API");
    const prs = await fetchPullRequests();

    try {
      sessionStorage.setItem(
        CONFIG.cacheKey,
        JSON.stringify({
          data: prs,
          timestamp: Date.now(),
        }),
      );
    } catch (e) {
      console.warn("Could not cache PR data:", e);
    }

    return prs;
  }

  /**
   * Find PR that matches a commit SHA
   */
  function findPRForCommit(prs, commitSha) {
    const shortSha = commitSha.substring(0, 11);

    return prs.find((pr) => {
      const branch = pr.head_ref;
      return (
        branch.startsWith(CONFIG.branchPrefix) && branch.includes(shortSha)
      );
    });
  }

  /**
   * Get PR state from PR object
   */
  function getPRState(pr) {
    if (pr.merged_at) return "merged";
    if (pr.state === "closed") return "closed";
    return "open";
  }

  /**
   * Update DOM element with PR status
   */
  function updatePRStatus(element, commitSha, pr) {
    element.classList.remove("pr-loading");

    if (pr) {
      const state = getPRState(pr);
      const stateInfo = PR_STATES[state];

      element.innerHTML = `
        <a href="${pr.html_url}" 
           target="_blank" 
           class="pr-link ${stateInfo.class}" 
           title="${stateInfo.label}: ${pr.title}">
          ${stateInfo.icon} #${pr.number}
        </a>
      `;
    } else {
      // No PR found - leave empty (user can copy SHA and trigger workflow manually)
      element.innerHTML = `<span class="pr-none" title="No PR found">—</span>`;
    }
  }

  /**
   * Initialize PR status checking
   */
  async function init() {
    const configEl = document.getElementById("pr-status-config");
    if (!configEl) {
      console.log("PR status: no config element found, skipping");
      return;
    }

    try {
      const pageConfig = JSON.parse(configEl.dataset.config);
      CONFIG.repoOwner = pageConfig.owner;
      CONFIG.repoName = pageConfig.repo;
    } catch (e) {
      console.error("PR status: invalid config", e);
      return;
    }

    const prStatusElements = document.querySelectorAll(".pr-status[data-sha]");
    if (prStatusElements.length === 0) return;

    prStatusElements.forEach((el) => {
      el.classList.add("pr-loading");
      el.innerHTML = "⏳";
    });

    const prs = await fetchPRsWithCache();

    prStatusElements.forEach((element) => {
      const sha = element.dataset.sha;
      const pr = findPRForCommit(prs, sha);
      updatePRStatus(element, sha, pr);
    });

    console.log(
      `PR status: checked ${prStatusElements.length} commits against ${prs.length} PRs`,
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
