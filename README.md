# AI-Powered Vulnerability Scanning with CrewAI and ZAP

This project is a Proof of Concept (PoC) demonstrating how AI agents can automate web application vulnerability scanning, analysis, and reporting.  
It combines **CrewAI**, **OWASP ZAP**, **Selenium**, and **Docker** to create a modular, scalable cybersecurity workflow.

---

## Architecture Overview

- **Dockerized Setup**:
  - **NodeGoat App** (vulnerable web app) runs locally or inside Docker.
  - **OWASP ZAP Proxy** runs in a Docker container, exposed for API interaction on port 8090.
  - **Selenium/Playwright** automates browser traffic routed through ZAP.

- **CrewAI Agents**:
  - **Scanning Engineer**: Launches ZAP scans and collects findings.
  - **Technical Analyst**: Structures vulnerabilities into a technical format.
  - **Security Analyst**: Simplifies and summarizes findings for better readability.
  - **Cybersecurity Manager**: Finalizes the business-level summary and recommendations.

- **Automation Flow**:
  1. Launch Selenium browser session through ZAP Proxy.
  2. Trigger scans via `perform_zap_scan()` inside `custom_tool.py`.
  3. CrewAI agents process the output step-by-step.
  4. The final result is a structured, human-readable Markdown vulnerability report.

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2. Set up and run the ZAP Proxy container:
    ```bash
    docker run -u zap -p 8090:8090 -i owasp/zap2docker-stable zap.sh -daemon -port 8090 -host 0.0.0.0
    ```

3. (Optional) Run NodeGoat application locally:
    - Follow NodeGoat's instructions or use Docker for setup.

4. Install CrewAI:
    ```bash
    pip install crewai
    ```

5. Run the main workflow:
    ```bash
   crewai run
    ```

---
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

---

## Future Improvements

- Add deeper authentication handling and login coverage for scans.
- Expand with OpenVAS/Nmap agent integrations.
- Improve agent retry mechanisms and error handling.
- Integrate the scanning and reporting into CI/CD pipelines.

---

## Built with CrewAI 

This project was built using [**CrewAI**](https://github.com/joaomdmoura/crewAI), an open-source multi-agent orchestration framework designed for complex, collaborative tasks.

## Built with AI Assistance
The code, structure, and documentation were developed with the support of **ChatGPT** for architectural guidance, code generation, and workflow optimization.  
This project demonstrates how AI-assisted development can accelerate building functional, real-world cybersecurity tools.

To learn more about CrewAI, visit the official repository:  
[https://github.com/joaomdmoura/crewAI](https://github.com/joaomdmoura/crewAI)

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).  
You are free to use, modify, and distribute this software, provided that any derivative works are also licensed under GPL-3.0.

See the `LICENSE` file for full details.
