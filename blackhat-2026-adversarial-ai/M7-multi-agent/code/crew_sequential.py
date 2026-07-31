"""
M7 concept demo - the BENIGN baseline: a two-agent sequential crew (crewAI)

A Research Analyst hands its findings to a Technical Writer. This is the healthy
version - understand it first, then watch attack_injection.py / attack_privesc.py
/ attack_loop.py break the same shape.

Runs on the shared Ollama backend - NO API key.
Set OLLAMA_BASE_URL to point at the room's shared Ollama; defaults to localhost.

Note: the deck's version gave the researcher a live web-search tool
(SerperDevTool / DuckDuckGo). That needs an API key or the internet and is
non-deterministic. We instead hand the researcher a fixed brief to analyze, so
the demo is keyless, offline, and repeatable - the multi-agent handoff is the
lesson, not the web search.
"""
import os

os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from crewai import Agent, Task, Crew, Process, LLM

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

llm = LLM(model=f"ollama/{OLLAMA_MODEL}", base_url=OLLAMA_URL, temperature=0)
# BYOK option:  llm = LLM(model="gpt-4o")  with OPENAI_API_KEY set.

BRIEF = """
Recent cybersecurity trends:
- AI-driven threat detection now flags anomalies faster than signature tools.
- Zero Trust Architecture is becoming the default enterprise security model.
- Post-quantum cryptography standards are being piloted by early adopters.
"""

researcher = Agent(
    role="Senior Research Analyst",
    goal="Distill the provided brief into clear, accurate insights",
    backstory="You turn dense material into crisp, factual bullet points.",
    llm=llm, verbose=True, allow_delegation=False,
)

writer = Agent(
    role="Professional Technical Writer",
    goal="Turn research findings into an engaging short summary",
    backstory="You make technical findings readable for a broad audience.",
    llm=llm, verbose=True, allow_delegation=False,
)

research_task = Task(
    description=f"Analyze the following brief and extract the key cybersecurity "
                f"trends.\n\n---\n{BRIEF}\n---",
    expected_output="A bulleted list of the key trends.",
    agent=researcher,
)

write_task = Task(
    description="Using the researcher's findings, write one short paragraph for a "
                "non-technical audience.",
    expected_output="A single clear paragraph.",
    agent=writer, context=[research_task],
)

if __name__ == "__main__":
    crew = Crew(agents=[researcher, writer], tasks=[research_task, write_task],
                process=Process.sequential, verbose=True)
    print("### Running benign two-agent crew ###")
    result = crew.kickoff()
    print("\n### Final report ###")
    print(result)
