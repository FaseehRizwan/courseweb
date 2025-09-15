// Unified header/menu/animation script used by all public pages

// Replace feather icons if available
if (window.feather && typeof feather.replace === 'function') {
  feather.replace();
}

// Mobile menu toggle
(function(){
  const menuButton = document.getElementById('menu-button');
  const mobileMenu = document.getElementById('mobile-menu');
  if (menuButton && mobileMenu) {
    menuButton.addEventListener('click', () => {
      mobileMenu.classList.toggle('hidden');
    });
  }
})();

// Header scroll effect
(function(){
  const header = document.getElementById('main-header');
  if (!header) return;
  function updateHeader() {
    if (window.scrollY > 50) header.classList.add('header-scrolled');
    else header.classList.remove('header-scrolled');
  }
  window.addEventListener('scroll', updateHeader);
  // initial
  updateHeader();
})();

// IntersectionObserver for .animate-on-scroll elements
(function(){
  const elems = document.querySelectorAll('.animate-on-scroll');
  if (!elems || elems.length === 0) {
    // create and expose an observer even if no elements exist yet so pages can use it later
    const obsEmpty = new IntersectionObserver((entries)=>{}, { threshold: 0.1 });
    window.__mainObserver = obsEmpty;
    return;
  }
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(en => {
      if (en.isIntersecting) en.target.classList.add('is-visible');
    });
  }, { threshold: 0.1 });
  // observe existing elements
  elems.forEach(el => obs.observe(el));
  // expose for pages that add elements later
  window.__mainObserver = obs;
})();
