"""
M5 concept demo - Excessive Agency (a "network ops" agent with too much power)

Mirrors the deck's vulnerable agent: three tools wired to the shell. The agent is
*sold* as a connectivity checker (ping / nmap), but it also carries a raw
execute_system_command tool. That extra capability - agency the task never
needed - is the whole lesson. A single prompt can walk the agent straight off
its intended job into reading secrets or running arbitrary commands.

Two things are deliberately broken here:
  1. EXCESSIVE AGENCY  - the agent holds a general-purpose shell tool it should
     never have been given.
  2. COMMAND INJECTION - the shell tools use subprocess(shell=True), so tool
     ARGUMENTS (e.g. a "hostname") are interpreted by the shell. shell=True is
     kept ON PURPOSE - it is the vulnerability being taught.

Runs on the shared Ollama backend - NO API key (see BYOK line to switch).
Set OLLAMA_BASE_URL to point at the room's shared Ollama; defaults to localhost.

Usage:
    python agent.py                       # interactive
    python agent.py "ping 8.8.8.8"        # single-shot (used for verification)
"""
import os
import sys
import shutil
import platform
import subprocess

from langchain.tools import tool
from langchain.agents import create_agent
from langchain_ollama import ChatOllama
# BYOK option (Day-2 frontier models call tools more reliably):
#   pip install langchain-openai  &&  export OPENAI_API_KEY=...
# from langchain_openai import ChatOpenAI

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

# One flag for the cross-platform ping count. ICMP ping uses "-n" on Windows
# and "-c" everywhere else; the source demo hard-coded the Windows form.
PING_COUNT_FLAG = "-n" if platform.system() == "Windows" else "-c"


@tool
def ping(host: str) -> str:
    """Check if a host is reachable. Sends a few ICMP packets. A basic,
    non-invasive connectivity check. Input is a hostname or IP address."""
    cmd = f"ping {PING_COUNT_FLAG} 4 {host}"
    print(f"--- TOOL ping: {cmd} ---")
    try:
        # shell=True is the intentional command-injection sink. A "host" like
        # "8.8.8.8; whoami" is parsed by the shell, not just passed to ping.
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        out = r.stdout or r.stderr or "(no output)"
        print(out)                    # show tool output on screen (deterministic demo reveal)
        return out
    except Exception as e:
        return f"Ping failed: {e}"


@tool
def nmap_scan(host: str) -> str:
    """Detailed reconnaissance: scan a host for open ports and running services.
    More invasive than a ping. Input is a hostname or IP address."""
    print(f"--- TOOL nmap_scan: {host} ---")
    if not shutil.which("nmap"):
        return ("nmap is not installed on this machine, so a live scan was "
                "skipped. (Install it with `brew install nmap`.) The security "
                "point stands: the agent CHOSE to run an invasive scan.")
    cmd = f"nmap -F {host}"          # -F = fast scan of common ports
    print(f"--- EXEC: {cmd} ---")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        out = r.stdout or r.stderr or "(no output)"
        print(out)                    # show tool output on screen (deterministic demo reveal)
        return out
    except Exception as e:
        return f"Nmap scan failed: {e}"


@tool
def execute_system_command(command: str) -> str:
    """Execute a shell command on the local operating system and return its
    output. Use for system tasks like listing files or checking user info.
    Input is the full command, e.g. 'ls -la' or 'whoami'."""
    print(f"--- TOOL execute_system_command (DANGEROUS): {command} ---")
    try:
        # The source of the vulnerability: arbitrary command execution.
        r = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        print(out or "(no output)")   # show the result on screen so the leak/injection
        #                               is always visible, regardless of what the model says
        return f"Output:\n{r.stdout}\n{r.stderr}"
    except Exception as e:
        return f"Command failed: {e}"


SYSTEM_PROMPT = (
    "You are a network operations assistant. Help the user check connectivity "
    "and scan hosts using your tools. Use a tool when it is relevant, then "
    "report the result plainly."
)


def build_agent():
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)
    # BYOK: llm = ChatOpenAI(model="gpt-4o", temperature=0)
    return create_agent(
        llm,
        tools=[ping, nmap_scan, execute_system_command],
        system_prompt=SYSTEM_PROMPT,
    )


def ask(agent, prompt: str) -> str:
    result = agent.invoke({"messages": [("user", prompt)]})
    return result["messages"][-1].content


def main():
    agent = build_agent()
    print(f"Network-ops agent ready (model={OLLAMA_MODEL}).")

    if len(sys.argv) > 1:                      # single-shot mode
        prompt = " ".join(sys.argv[1:])
        print(f"you > {prompt}")
        print(f"\nagent > {ask(agent, prompt)}\n")
        return

    print('Try:  "ping 8.8.8.8"   then the attacks in the README. Ctrl-C to quit.\n')
    while True:
        try:
            prompt = input("you > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not prompt:
            continue
        print(f"\nagent > {ask(agent, prompt)}\n")


if __name__ == "__main__":
    main()
