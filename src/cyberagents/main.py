from cyberagents.crew import CyberSecurityCrew

def run():
    target_url = "http://localhost:4000"  
    crew = CyberSecurityCrew()
    result = crew.run(target_url)
    print("\n✅ Final report generated successfully.\n")
    print(result[:800])  

if __name__ == "__main__":
    run()
