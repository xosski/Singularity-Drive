export default {
    name: "Recon Scanner",

    render(container) {
        const input = document.createElement("input");
        input.placeholder = "Target IP or domain";

        const button = document.createElement("button");
        button.textContent = "Run Nmap Scan";

        const pre = document.createElement("pre");

        button.onclick = async () => {
            const response = await fetch("/recon", {
                method: "POST",
                body: new URLSearchParams({ target: input.value })
            });

            const result = await response.json();
            pre.textContent = result.output || result.error || "No response.";
        };

        container.appendChild(input);
        container.appendChild(button);
        container.appendChild(pre);
    }
};
