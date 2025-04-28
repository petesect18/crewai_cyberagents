
# AI-Powered Vulnerability Scanning with CrewAI and ZAP

A Proof of Concept (PoC) demonstrating how AI agents can automate web application vulnerability scanning, analysis, and reporting.  
This project combines **CrewAI**, **OWASP ZAP**, **Selenium**, and **Docker** to create a modular, scalable cybersecurity workflow.

---

## Architecture Overview

- **Dockerized Setup**:
  - **NodeGoat App** (vulnerable web app) runs locally or inside Docker.
  - **OWASP ZAP Proxy** container runs on port `8090` to capture and analyze traffic.
  - **Selenium/Playwright** browser automation routes traffic through ZAP.

- **CrewAI Agents**:
  - **Scanning Engineer**: Launches ZAP scans and collects findings.
  - **Technical Analyst**: Organizes vulnerabilities into a structured format.
  - **Security Analyst**: Simplifies and summarizes technical findings.
  - **Cybersecurity Manager**: Finalizes business-level summaries and recommendations.

- **Automation Flow**:
  1. Launch Selenium browser session through ZAP.
  2. Trigger scans via `perform_zap_scan()` from `custom_tool.py`.
  3. CrewAI agents process results, step-by-step.
  4. Generate a human-readable Markdown report.

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2. Set up and run ZAP Proxy container:
    ```bash
    docker run -u zap -p 8090:8090 -i owasp/zap2docker-stable zap.sh -daemon -port 8090 -host 0.0.0.0
    ```

3. (Optional) Run NodeGoat application locally:
    - Follow NodeGoat's instructions or use Docker for setup.

4. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

5. Run the AI workflow:
    ```bash
    python main.py
    ```

---

## File Structure

| File / Folder       | Purpose                                           |
|---------------------|---------------------------------------------------|
| `main.py`            | Entry point — launches CrewAI agents             |
| `crew.py`            | Defines agents, tasks, and communication flow    |
| `custom_tool.py`     | Contains `perform_zap_scan()` automation logic   |
| `agents.yaml`        | Agent configuration                              |
| `tasks.yaml`         | Task and workflow configuration                  |
| `output/`            | Contains generated Markdown reports             |

---

## System Diagram

```
[NodeGoat App] --> [Selenium Browser] --> [ZAP Proxy (Docker)] --> [CrewAI Agents] --> [Markdown Report]
```
## Future Improvements

- Add deeper authentication handling for scans.
- Introduce OpenVAS/Nmap agent integrations.
- Improve agent retry/error-handling logic.
- Enable direct CI/CD pipeline integration.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.


#🤖 Built with AI Collaboration

This project was designed and developed with assistance from AI tools for architecture planning, coding support, and workflow optimization — illustrating AI’s role in building next-generation cybersecurity solutions.

