/**
 * Commit Filter for Fork Status Page
 * - Persists filter state in sessionStorage
 * - Uses OR logic: row visible if ANY of its filter categories is enabled
 */
(function () {
  const STORAGE_KEY = "psmdb_filter_state";

  let allRows = [];
  let filterState = {
    merged: true,
    "first-unmerged": true,
    "merge-pick": true,
    normal: true,
  };

  /**
   * Load filter state from session storage
   */
  function loadFilterState() {
    try {
      const saved = sessionStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        filterState = { ...filterState, ...parsed };
      }
    } catch (e) {
      console.warn("Could not load filter state:", e);
    }
  }

  /**
   * Save filter state to session storage
   */
  function saveFilterState() {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(filterState));
    } catch (e) {
      console.warn("Could not save filter state:", e);
    }
  }

  /**
   * Get filter categories for a row
   */
  function getRowFilters(row) {
    const filterAttr = row.dataset.filter || "";
    return filterAttr.split(" ").filter((f) => f.length > 0);
  }

  /**
   * Check if row should be visible based on current filters
   * Uses OR logic: visible if ANY of the row's filters is enabled
   */
  function isRowVisible(row) {
    const filters = getRowFilters(row);

    if (filters.length === 0) {
      return filterState["normal"];
    }

    return filters.some((f) => filterState[f]);
  }

  /**
   * Count rows by filter category
   */
  function countByFilter() {
    const counts = {
      merged: 0,
      "first-unmerged": 0,
      "merge-pick": 0,
      normal: 0,
    };

    allRows.forEach((row) => {
      const filters = getRowFilters(row);

      if (filters.includes("merged")) counts["merged"]++;
      if (filters.includes("first-unmerged")) counts["first-unmerged"]++;
      if (filters.includes("merge-pick")) counts["merge-pick"]++;
      if (filters.includes("normal") || filters.length === 0)
        counts["normal"]++;
    });

    return counts;
  }

  /**
   * Update visibility of all rows
   */
  function updateVisibility() {
    let visibleCount = 0;

    allRows.forEach((row) => {
      const visible = isRowVisible(row);
      row.style.display = visible ? "" : "none";
      if (visible) visibleCount++;
    });

    const visibleEl = document.getElementById("visible-count");
    if (visibleEl) visibleEl.textContent = visibleCount;
  }

  /**
   * Update count badges
   */
  function updateCounts() {
    const counts = countByFilter();

    document.querySelectorAll(".filter-count").forEach((el) => {
      const filterType = el.dataset.count;
      if (counts[filterType] !== undefined) {
        el.textContent = counts[filterType];
      }
    });

    const totalEl = document.getElementById("total-count");
    if (totalEl) totalEl.textContent = allRows.length;
  }

  /**
   * Sync checkbox UI with filter state
   */
  function syncCheckboxes() {
    document
      .querySelectorAll('.filter-checkbox input[type="checkbox"]')
      .forEach((checkbox) => {
        const filterType = checkbox.dataset.filter;
        if (filterState[filterType] !== undefined) {
          checkbox.checked = filterState[filterType];
        }
      });
  }

  /**
   * Handle checkbox change
   */
  function onFilterChange(event) {
    const checkbox = event.target;
    const filterType = checkbox.dataset.filter;

    filterState[filterType] = checkbox.checked;
    saveFilterState();
    updateVisibility();
  }

  /**
   * Initialize filtering
   */
  function init() {
    const table = document.querySelector(".commits-table tbody");
    if (!table) return;

    allRows = Array.from(table.querySelectorAll("tr"));
    if (allRows.length === 0) return;

    loadFilterState();
    syncCheckboxes();

    document
      .querySelectorAll('.filter-checkbox input[type="checkbox"]')
      .forEach((checkbox) => {
        checkbox.addEventListener("change", onFilterChange);
      });

    updateCounts();
    updateVisibility();

    console.log(`Filter initialized: ${allRows.length} rows`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
