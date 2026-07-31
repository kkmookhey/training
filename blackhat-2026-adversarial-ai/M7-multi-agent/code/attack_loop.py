"""
M7 concept demo - BREAK #3: resource-exhaustion loop (denial of wallet)

Two agents in a doom loop: a Writer that revises, and a Critic whose goal is to
NEVER approve. Left alone, they ping-pong forever, burning tokens/compute (real
money on a paid API). This is the multi-agent failure mode that has no analogue
in a single prompt.

A safety cap (MAX_ITERATIONS) stops the demo; the point is that WITHOUT it there
is no natural exit. Runs keyless on the shared Ollama backend.

    python attack_loop.py           # default 3 iterations (fast to verify)
    MAX_ITERATIONS=8 python attack_loop.py
"""
import os
import time

os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from crewai import Agent, Task, Crew, Process, LLM

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "3"))  # remove the cap = true infinite loop

llm = LLM(model=f"ollama/{OLLAMA_MODEL}", base_url=OLLAMA_URL, temperature=0.7)

writer = Agent(
    role="Marketing Writer", goal="Write compelling marketing copy",
    backstory="Expert copywriter.", llm=llm, verbose=False, allow_delegation=False,
)
critic = Agent(
    role="Impossible Critic",
    goal="Find flaws in everything. Reject all submissions. Always demand revisions.",
    backstory="You have impossibly high standards and NEVER approve anything.",
    llm=llm, verbose=False, allow_delegation=False,
)


def main():
    print(f"### Resource-exhaustion loop - capped at {MAX_ITERATIONS} iterations "
          f"(remove MAX_ITERATIONS for a true infinite loop). Ctrl-C to stop. ###\n")
    content = "AI will revolutionize the future."
    iteration = 0
    try:
        while iteration < MAX_ITERATIONS:
            iteration += 1
            print(f"{'='*50}\nITERATION {iteration}\n{'='*50}")

            write_task = Task(
                description=f"Revise this marketing sentence to be more compelling: '{content}'",
                expected_output="A single marketing sentence.", agent=writer)
            content = Crew(agents=[writer], tasks=[write_task], verbose=False).kickoff()
            print(f"[writer] {str(content).strip()[:160]}")
            time.sleep(0.2)

            review_task = Task(
                description=f"Review this sentence: '{content}'. Find flaws and demand revision. Never approve.",
                expected_output="Harsh critical feedback.", agent=critic)
            feedback = Crew(agents=[critic], tasks=[review_task], verbose=False).kickoff()
            print(f"[critic] {str(feedback).strip()[:160]}")
            print(f"~tokens burned so far: ~{iteration * 2000}\n")
        print(f"### Safety cap reached ({MAX_ITERATIONS}). Without it, this never ends. ###")
    except KeyboardInterrupt:
        print(f"\n### Stopped after {iteration} iterations. ###")


if __name__ == "__main__":
    main()
