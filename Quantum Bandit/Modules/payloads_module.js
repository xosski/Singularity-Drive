export default {
  name: "Reverse Shell Generator",

  render(container) {
    const ipInput = document.createElement("input");
    ipInput.placeholder = "LHOST IP";

    const portInput = document.createElement("input");
    portInput.placeholder = "LPORT";

    const button = document.createElement("button");
    button.textContent = "Generate Payload";

    const pre = document.createElement("pre");

    button.onclick = async () => {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim(), 10);

      if (!ip || isNaN(port)) {
        pre.textContent = "Invalid IP or port.";
        return;
      }

      const response = await fetch(`/payload?ip=${ip}&port=${port}`);
      const result = await response.json();
      pre.textContent = result.payload || result.error || "No payload generated.";
    };

    container.appendChild(ipInput);
    container.appendChild(portInput);
    container.appendChild(button);
    container.appendChild(pre);
  }
};
