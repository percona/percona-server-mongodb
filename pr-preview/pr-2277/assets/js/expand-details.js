/**
 * Expand/Collapse Details Column
 * - Clicking on truncated details expands to show full content
 * - Clicking again collapses back to truncated view
 */
(function () {
  /**
   * Toggle expanded state on click
   */
  function onDetailsClick(event) {
    const element = event.currentTarget;
    const expanded = element.classList.toggle("expanded");
    element.setAttribute("aria-expanded", expanded ? "true" : "false");
    element.setAttribute(
      "aria-label",
      expanded ? "Click to collapse details" : "Click to expand details"
    );
  }

  /**
   * Initialize expand/collapse for details cells
   */
  function init() {
    document.querySelectorAll(".col-details-content").forEach((element) => {
      // Only add click handler if there's content
      if (element.textContent.trim()) {
        element.addEventListener("click", onDetailsClick);
        element.setAttribute("role", "button");
        element.setAttribute("tabindex", "0");
        element.setAttribute("aria-expanded", "false");
        element.setAttribute(
          "aria-label",
          "Click to expand details"
        );

        // Also handle keyboard activation
        element.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onDetailsClick(event);
          }
        });
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
