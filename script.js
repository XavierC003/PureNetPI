document.addEventListener("DOMContentLoaded", () => {
    const blocklistElement = document.getElementById("blocklist");
    if (blocklistElement) {
        fetch("/api/blocklist")
            .then(response => response.json())
            .then(data => {
                data.forEach(domain => {
                    let li = document.createElement("li");
                    li.textContent = domain;
                    blocklistElement.appendChild(li);
                });
            });
    }

    const submitForm = document.getElementById("submitForm");
    if (submitForm) {
        submitForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const domain = document.getElementById("domain").value;

            fetch("/api/blocklist", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById("message").textContent = data.message || data.error;
                document.getElementById("domain").value = "";
            });
        });
    }
});

function downloadBlocklist() {
    fetch("/api/blocklist")
        .then(response => response.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = "blocklist.json";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
}

