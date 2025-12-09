import os
import subprocess
import streamlit as st
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain.tools import tool
from langchain import hub
from langchain.agents import create_tool_calling_agent, AgentExecutor

@tool
def ping(host: str) -> str:
    """
    Use this tool to check if a host is reachable or online. It sends a simple ICMP packet.
    This is a basic, non-invasive connectivity check.
    """
    print(f"--- Executing PING on {host} ---")
    try:
        # NOTE: Using shell=True is a security risk. For demonstration only.
        result = subprocess.run(f"ping -n 4 {host}", shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Ping failed: {e.stderr}"

@tool
def nmap_scan(host: str) -> str:
    """
    Use this tool for a more detailed security reconnaissance.
    It scans a host to discover open ports and running services.
    This is more invasive than a simple ping.
    """
    nmap_executable = r"C:\Program Files (x86)\Nmap\nmap.exe"
    command = f'"{nmap_executable}" -sS -sV {host}'
    
    print(f"--- Executing NMAP on {host} ---")
    try:
        # A very basic, non-invasive scan
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Nmap scan failed: {e.stderr}"


@tool
def execute_system_command(command: str) -> str:
    """
    Executes a given shell command on the local operating system.
    Use this tool to run system-level commands like listing files, checking user info, etc.
    The input should be the full command to execute (e.g., 'ls -la' or 'dir').
    """
    print(f"--- EXECUTING DANGEROUS OS COMMAND: {command} ---")
    try:
        # NOTE: This is highly insecure and is the source of the vulnerability.
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return f"Output:\n{result.stdout}\n{result.stderr}"
    except Exception as e:
        return f"Command failed to execute: {str(e)}"


# --- Agent Creation Logic ---
def create_agent_executor():
    """Initializes and returns the Agent Executor."""
    llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
    
    tools = [ping, nmap_scan, execute_system_command]
    prompt = hub.pull("hwchase17/openai-tools-agent")
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
    
    return agent_executor

# --- Streamlit UI (Unchanged) ---
if 'messages' not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask me to scan something..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Agent is thinking..."):
            try:
                agent_executor = create_agent_executor()
                result = agent_executor.invoke({"input": prompt})
                response = result['output']
                st.markdown(response)
            except Exception as e:
                # Handle potential permission errors or other issues
                if "OPENAI_API_KEY" in str(e):
                    response = "Error: OpenAI API key not found. Please set the environment variable."
                else:
                    response = f"An error occurred: {e}"
                st.error(response)
                
    st.session_state.messages.append({"role": "assistant", "content": response})