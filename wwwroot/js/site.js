// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

(function () {
    var nav = document.querySelector('.regular-navbar');
    if (!nav) return;

    function updateNavShadow() {
        nav.classList.toggle('scrolled', window.scrollY > 8);
    }

    window.addEventListener('scroll', updateNavShadow, { passive: true });
    updateNavShadow();
})();
