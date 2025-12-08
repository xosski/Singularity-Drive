export default {
    name: "XSS Tester",
    description: "Simulated XSS analysis",

    render(container) {
        const input = document.createElement("input");
        input.placeholder = "Enter text to test (simulation only)";

        const button = document.createElement("button");
        button.textContent = "Analyze (Simulated)";

        const pre = document.createElement("
