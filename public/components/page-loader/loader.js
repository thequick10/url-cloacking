// loader.js
(function () {
  const TRANSITION_DURATION = 600; // in ms
  const HIDE_DELAY = 1000; // delay before hiding the loader
  let hideTimeout = null;

  /**
   * Creates and injects loader HTML if it doesn't exist
   */
  function injectLoader() {
    if (document.getElementById("page-loader")) return;

    const loader = document.createElement("div");
    loader.id = "page-loader";
    loader.innerHTML = `
      <div class="glass-card">
        <div class="spinner"></div>
        <p class="loading-text">Loading, Please Wait...</p>
      </div>
    `;
    document.body.prepend(loader);

    // Hide initially
    loader.style.display = "none";
    loader.style.opacity = "0";
  }

  /**
   * Show loader immediately
   * 
   */
  function showLoader(message = "Loading, Please Wait...") {
    injectLoader();
    const loader = document.getElementById("page-loader");
    const text = loader.querySelector(".loading-text");

    if (text) text.textContent = message;

    if (hideTimeout) {
      clearTimeout(hideTimeout);
      hideTimeout = null;
    }

    loader.style.display = "flex";
    requestAnimationFrame(() => {
      loader.style.opacity = "1";
    });
  }

  /**
   * Hide loader with delay
   * @param {number} delay
   */
  function hideLoader(delay = HIDE_DELAY) {
    const loader = document.getElementById("page-loader");
    if (!loader) return;

    hideTimeout = setTimeout(() => {
      loader.style.opacity = "0";
      setTimeout(() => {
        loader.style.display = "none";
        hideTimeout = null;
      }, TRANSITION_DURATION);
    }, delay);
  }

  /**
   * Automatically show loader and hide on page load
   */
  function enableAutoLoader() {
    showLoader();
    window.addEventListener("load", () => {
      hideLoader();
    });
  }

  // Expose globally
  window.PageLoader = {
    show: showLoader,
    hide: hideLoader,
    auto: enableAutoLoader
  };

  // ✅ Auto-start loader on page load
  enableAutoLoader();
})();
