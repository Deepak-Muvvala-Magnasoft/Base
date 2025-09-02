document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll('.image-card').forEach(card => {
    card.addEventListener('click', function(e) {
        const url = this.getAttribute('href');
        if (url.startsWith('http')) {
            return;
        }
    });
  });
});
