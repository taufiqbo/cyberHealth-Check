// Small progressive enhancements; every page also works without JavaScript.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });
  document.querySelectorAll(".js-hide").forEach(function (el) { el.hidden = true; });
});
