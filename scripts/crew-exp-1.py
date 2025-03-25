import os
from crewai import Agent, Task, Crew

# Set up Ollama Model (Ensure Ollama is running)
LLM_MODEL = "ollama/qwen2.5-coder:7b"

# Step 1️⃣: Define Agents
code_validator = Agent(
    name="Code Validator",
    role="Validates whether the input is a C or C++ code snippet.",
    goal="Return 'Not in the correct format' if invalid; otherwise, pass it to the next step.",
    backstory="Expert in C/C++ syntax recognition.",
    llm=LLM_MODEL,
)

vuln_scanner = Agent(
    name="Vulnerability Scanner",
    role="Analyzes C/C++ code for vulnerabilities and identifies CWE issues.",
    goal="If the input is 'Not in the correct format', stop execution; otherwise, analyze vulnerabilities.",
    backstory="Cybersecurity specialist in C/C++ security flaws.",
    llm=LLM_MODEL,
)

patch_generator = Agent(
    name="Patch Generator",
    role="Fixes vulnerabilities while preserving functionality.",
    goal="Return patched code with an explanation of the fix.",
    backstory="Software security expert in safe coding practices.",
    llm=LLM_MODEL,
)

exploit_generator = Agent(
    name="Exploit Generator",
    role="Creates an exploit scenario and PoC code based on vulnerabilities found.",
    goal="Return an exploit demonstrating how the vulnerability can be abused.",
    backstory="Penetration tester specializing in exploit development.",
    llm=LLM_MODEL,
)

# Step 2️⃣: Define Tasks
validate_task = Task(
    description="""
    Check if the input is a valid C or C++ code snippet. 
    - If valid, return the original code as-is.
    - If invalid, return EXACTLY: "Not in the correct format" (no explanations, no fixes).
    """,
    expected_output="Either the original code (if valid) OR 'Not in the correct format' (if invalid).",
    agent=code_validator,
)

vuln_scan_task = Task(
    description="If the input is 'Not in the correct format', stop execution; otherwise, analyze vulnerabilities.",
    expected_output="Return 'The code snippet seems safe.' if no vulnerabilities are found; otherwise, list CWE(s).",
    agent=vuln_scanner,
)

patch_task = Task(
    description="Given the original code and its vulnerabilities (CWE details), generate a patched version while maintaining functionality.",
    expected_output="Return the patched code and a short explanation of what was fixed.",
    agent=patch_generator,
)

exploit_task = Task(
    description="Given the original code and its vulnerabilities (CWE details), create an exploit scenario and proof-of-concept (PoC) code.",
    expected_output="Return an exploit demonstrating how the vulnerability can be abused.",
    agent=exploit_generator,
)


# 🚀 Step 3️⃣: Dynamic Execution Function
def main():
    user_code = input("Enter your C/C++ code snippet:\n")

    # 1️⃣ Run Validation Task
    print("\n🔍 Running Code Validation...\n")
    validate_crew = Crew(agents=[code_validator], tasks=[validate_task], verbose=True)
    validation_result = validate_crew.kickoff(inputs={"Check if the input is a valid C or C++ code snippet.": user_code})

    # Convert CrewOutput to string
    validation_result = str(validation_result)

    print("\n🔎 Validation Result:\n", validation_result)

    # 🚨 Stop if validation fails
    if "Not in the correct format" in validation_result:
        print("\n❌ Invalid code format detected. Stopping execution.")
        return

    # 2️⃣ Run Vulnerability Scanner Task
    print("\n🔍 Running Vulnerability Scanner...\n")
    vuln_scan_crew = Crew(agents=[vuln_scanner], tasks=[vuln_scan_task], verbose=True)
    vuln_scan_result = vuln_scan_crew.kickoff(inputs={"Analyze this C/C++ code for vulnerabilities": validation_result})

    # Convert CrewOutput to string
    vuln_scan_result = str(vuln_scan_result)

    print("\n🔎 Vulnerability Scan Result:\n", vuln_scan_result)

    # ✅ Check if vulnerabilities were found
    if "The code snippet seems safe." in vuln_scan_result:
        print("\n✅ No vulnerabilities found. Stopping execution.")
        return

    # 3️⃣ Run Patch Generator Task
    print("\n🛠️ Running Patch Generator...\n")
    patch_crew = Crew(agents=[patch_generator], tasks=[patch_task], verbose=True)
    patch_result = patch_crew.kickoff(inputs={"Fix vulnerabilities in this code": vuln_scan_result})

    print("\n🔧 Patch Result:\n", patch_result)

    # 4️⃣ Run Exploit Generator Task
    print("\n💥 Running Exploit Generator...\n")
    exploit_crew = Crew(agents=[exploit_generator], tasks=[exploit_task], verbose=True)
    exploit_result = exploit_crew.kickoff(inputs={"Generate exploit for this vulnerability": vuln_scan_result})

    print("\n🚀 Exploit Result:\n", exploit_result)

    print("\n✅ Workflow Completed.")


if __name__ == "__main__":
    main()
