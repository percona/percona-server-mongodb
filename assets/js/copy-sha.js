/**
 * Copy SHA to Clipboard
 * - Adds click handler to copy buttons
 * - Shows visual feedback on copy
 * - Announces result to screen readers via aria-live
 */
(function () {
  const LIVE_REGION_ID = "copy-sha-announcer";

  /**
   * Get or create the live region for screen reader announcements
   */
  function getLiveRegion() {
    let el = document.getElementById(LIVE_REGION_ID);
    if (!el) {
      el = document.createElement("div");
      el.id = LIVE_REGION_ID;
      el.setAttribute("aria-live", "polite");
      el.setAttribute("aria-atomic", "true");
      el.setAttribute("role", "status");
      el.className = "visually-hidden";
      el.style.cssText =
        "position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0";
      document.body.appendChild(el);
    }
    return el;
  }

  /**
   * Copy text to clipboard
   */
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand("copy");
        document.body.removeChild(textarea);
        return true;
      } catch (e) {
        document.body.removeChild(textarea);
        return false;
      }
    }
  }

  /**
   * Show feedback on button and announce to screen readers
   */
  function showFeedback(button, success) {
    const originalText = button.textContent;
    const originalLabel = button.getAttribute("aria-label") || "Copy full SHA";
    button.textContent = success ? "✓" : "✗";
    button.classList.add(success ? "copied" : "copy-failed");
    button.setAttribute("aria-label", success ? "Copied" : "Copy failed");

    const liveRegion = getLiveRegion();
    liveRegion.textContent = success ? "SHA copied to clipboard" : "Copy failed";

    setTimeout(() => {
      button.textContent = originalText;
      button.setAttribute("aria-label", originalLabel);
      button.classList.remove("copied", "copy-failed");
      liveRegion.textContent = "";
    }, 1500);
  }

  /**
   * Handle copy button click
   */
  async function onCopyClick(event) {
    const button = event.currentTarget;
    const sha = button.dataset.sha;

    if (!sha) return;

    const success = await copyToClipboard(sha);
    showFeedback(button, success);
  }

  /**
   * Initialize copy buttons
   */
  function init() {
    document.querySelectorAll(".copy-sha-btn").forEach((button) => {
      button.addEventListener("click", onCopyClick);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
