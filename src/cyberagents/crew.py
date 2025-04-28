import os
import yaml
import pprint
from datetime import datetime
from urllib.parse import urlparse
from crewai import Agent, Task, Crew
from langchain_openai import ChatOpenAI
from .tools.custom_tool import perform_zap_scan


class CyberSecurityCrew:
    def __init__(self, config_path=None, debug=True):
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), "config")
        self.agents = {}
        self.tasks = {}
        self.debug = debug

    def load_agents(self):
        agent_file_path = os.path.join(self.config_path, "agents.yaml")
        if self.debug:
            print(f"\n📄 Looking for agents file at: {agent_file_path}")

        with open(agent_file_path, "r") as f:
            content = f.read()
            if self.debug:
                print("\n📂 Raw file content:")
                print(content)
            f.seek(0)
            agents_yaml = yaml.safe_load(f)

        if self.debug:
            print("\n🔍 Parsed YAML content:")
            pprint.pprint(agents_yaml)

        if 'agents' not in agents_yaml:
            raise ValueError("❌ 'agents' key not found in parsed YAML.")

        for agent_def in agents_yaml['agents']:
            self.agents[agent_def['name']] = Agent(
                role=agent_def['role'],
                goal=agent_def['goal'],
                backstory=agent_def['backstory'],
                llm=ChatOpenAI(**agent_def['llm']),
                allow_delegation=True
            )

    def load_tasks(self, url):
        with open(f"{self.config_path}/tasks.yaml") as f:
            tasks_yaml = yaml.safe_load(f)

        for task_def in tasks_yaml['tasks']:
            description = task_def['description']

            if task_def['name'] == "zap_scan":
                print("\n🧪 Task: ZAP Scanning initiated...")
                scan_results = perform_zap_scan(url)

                if "No vulnerabilities found" in scan_results:
                    print("⚠️ No critical findings — consider reviewing manually or simulating deeper interaction.")
                    description += "\n\n⚠️ No major vulnerabilities were found. Review the scan logs for confirmation."
                else:
                    description += f"\n\nScan Results:\n{scan_results}"
                print("✅ Scan complete.")

            context = [self.tasks[ctx] for ctx in task_def.get('context', [])]

            self.tasks[task_def['name']] = Task(
                description=description,
                agent=self.agents[task_def['agent']],
                context=context,
                expected_output=task_def['expected_output']
            )

    def run(self, target_url):
        self.load_agents()
        self.load_tasks(target_url)

        crew = Crew(
            agents=list(self.agents.values()),
            tasks=list(self.tasks.values())
        )

        print("\n🚀 Running CyberSecurity CrewAI agents...\n")
        print("🔍 Technical Analyst reviewing scan data...")
        print("🧠 Security Analyst translating findings for execs...")
        print("📝 Manager finalizing the report...\n")

        result = crew.kickoff()

        # ✅ Save final report to Markdown file
        slug = urlparse(target_url).netloc.replace(":", "-")
        timestamp = datetime.now().strftime("%Y-%m-%d")
        report_path = f"final_report_{slug}_{timestamp}.md"

        with open(report_path, "w") as f:
            f.write(f"# 🛡️ Vulnerability Report for {target_url}\n")
            f.write(f"_Date: {timestamp}_\n\n---\n\n")
            f.write(str(result))

        print(f"📄 Final report saved to `{report_path}`\n")
        return str(result)
