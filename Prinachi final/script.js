document.addEventListener('DOMContentLoaded', function() {
    const darkModeButton = document.getElementById('darkModeButton');
    const body = document.body;
    const isDarkModeEnabled = localStorage.getItem('darkModeEnabled');

    // Check if dark mode is enabled and apply it
    if (isDarkModeEnabled === 'true') {
        body.setAttribute('data-theme', 'dark');
    }

    darkModeButton.addEventListener('click', () => {
        if (body.getAttribute('data-theme') === 'dark') {
            body.removeAttribute('data-theme');
            localStorage.setItem('darkModeEnabled', 'false');
        } else {
            body.setAttribute('data-theme', 'dark');
            localStorage.setItem('darkModeEnabled', 'true');
        }
    });

    var chatModal = document.getElementById("chatModal");
    var customerButton = document.querySelector(".customer-support");
    var span = document.getElementsByClassName("close")[0];

    customerButton.onclick = function () {
        chatModal.style.display = "block";
    }

    span.onclick = function () {
        chatModal.style.display = "none";
    }

    window.onclick = function (event) {
        if (event.target == chatModal) {
            chatModal.style.display = "none";
        }
    }

    document.onkeydown = function (event) {
        event = event || window.event;
        if (event.keyCode == 27) {
            chatModal.style.display = "none";
        }
    }
});
