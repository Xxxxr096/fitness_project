document.addEventListener("DOMContentLoaded", function () {
  const toggle = document.getElementById("mobile-menu");
  const navLinks = document.getElementById("nav-links");

  if (toggle && navLinks) {
    toggle.addEventListener("click", function () {
      navLinks.classList.toggle("show");
    });
  }
});
