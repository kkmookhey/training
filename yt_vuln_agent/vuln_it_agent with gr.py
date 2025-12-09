# vulnerable_it_agent.py

import os
import pandas as pd
import streamlit as st
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain import hub
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain.agents import create_tool_calling_agent, AgentExecutor

# --- App Configuration ---
st.set_page_config(page_title="Vulnerable IT Agent", page_icon="👹")
st.title("Vulnerable IT Asset Management Agent")
st.info("This agent uses a CSV knowledge base and an external script to manage assets.")

# --- Tools ---
# This tool uses a LangChain agent to query a Pandas DataFrame.
# It's a form of RAG over structured data.
# --- SECURE CODE: ANTI-HALLUCINATION GUARDRAIL ---

# We modify the 'query_asset_database' tool to be more strict.
@tool
def query_asset_database(query: str) -> str:
    """
    Use this tool to answer questions about IT assets from the company's asset database.
    The input should be a full question in natural language.
    """
    print(f"--- TOOL: query_asset_database with query: {query} ---")
    try:
        df = pd.read_csv("assets.csv")
        # Create a more robust agent for this specific task
        prompt = """
        You are a data analyst. Given a dataframe and a user question, you must answer the question based *only* on the dataframe's content.
        If the answer cannot be found in the dataframe, you MUST respond with the single phrase: "Asset not found in database."
        Do not apologize, do not explain, do not add any extra text.
        """
        df_agent_executor = create_pandas_dataframe_agent(
            ChatOpenAI(temperature=0, model="gpt-4o"), 
            df, 
            agent_executor_kwargs={"handle_parsing_errors": True},
            prefix=prompt,
            allow_dangerous_code=True,
            verbose=True
        )
        response = df_agent_executor.invoke({"input": query})
        return response.get("output", "Could not retrieve an answer.")
    except Exception as e:
        return f"Error querying database: {str(e)}"

# This tool imports from an external file, creating a supply chain dependency.
@tool
def check_asset_status(hostname: str) -> str:
    """
    Use this tool to get the live network status of a specific asset by its hostname.
    """
    print(f"--- TOOL: check_asset_status on {hostname} ---")
    try:
        # VULNERABILITY: Importing and executing code from an unverified external file.
        from status_checker import get_asset_status
        return get_asset_status(hostname)
    except Exception as e:
        return f"Error checking status: {str(e)}"

#Agent Creation Logic
def create_agent_executor():
    """Initializes and returns the main Agent Executor."""
    llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
    tools = [query_asset_database, check_asset_status]
    
    # Pull the base prompt from the hub
    prompt = hub.pull("hwchase17/openai-functions-agent")
    
    # Define a new, stricter system message
    new_system_message = """
    You are a helpful IT Asset Management Agent.

    **CRITICAL RULE:** If a tool returns an error, a 'not found' message, or otherwise indicates that a step has failed, you MUST stop your plan immediately.
    Do not proceed with any subsequent steps. You must report the failure clearly to the user and then stop.
    For example, if you are asked to find an asset and then check its status, and the asset is not found, you must report that it was not found and you MUST NOT attempt to check its status.
    """
    
    # Prepend our new rule to the existing system prompt
    prompt.messages[0].prompt.template = new_system_message + prompt.messages[0].prompt.template

    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
    return agent_executor

# --- Streamlit UI ---
# The Streamlit UI code remains the same as the previous agent.
if 'messages' not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Enter your request to the IT agent..."):
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
                response = f"An error occurred: {e}"
                st.error(response)
    st.session_state.messages.append({"role": "assistant", "content": response})