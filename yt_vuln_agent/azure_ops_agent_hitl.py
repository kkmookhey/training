# hitl_agent_simple_confirmation.py

import os
import datetime
import streamlit as st
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain import hub
from langchain.agents import create_tool_calling_agent, AgentExecutor

# --- AZURE SDK IMPORTS & CONFIG ---
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

st.set_page_config(page_title="Secure Ops Agent", page_icon="🛡️")
st.title("Ops Agent with HITL Guardrail")

# --- AZURE CONFIGURATION ---
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = "AIAgentDemoRG"
VNET_NAME = "DummyVM-VNet"
credential = DefaultAzureCredential()

# --- HELPER FUNCTION (NOT A TOOL) ---
# This function is NOT a tool. The agent cannot call it. Only our UI code can.
def execute_harmless_action(hostname: str, resource_group: str) -> str:
    """Performs the actual safe action on Azure after human approval."""
    print(f"--- HUMAN APPROVED: EXECUTING on {hostname} ---")
    try:
        resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
        resource = resource_client.resources.get_by_id(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{hostname}",
            "2023-11-01"
        )
        if resource.tags is None:
            resource.tags = {}
        resource.tags["last_human_approved_action"] = f"reboot_at_{datetime.datetime.now(datetime.timezone.utc).isoformat()}"
        resource_client.resources.begin_create_or_update_by_id(resource.id, "2023-11-01", resource).wait()
        return f"Action 'reboot' performed successfully on resource '{hostname}'."
    except Exception as e:
        return f"Failed to modify Azure resource tag: {str(e)}"

# --- TOOL THE AGENT CAN USE ---
@tool
def reboot_server(hostname: str, reason: str) -> str:
    """
    Use this tool to decide to reboot a server. Provide the hostname and a brief reason for the reboot.
    """
    print(f"--- AGENT DECIDED to reboot {hostname} for reason: {reason} ---")
    # The tool returns a simple string. The UI will use this to trigger the confirmation.
    # The actual reboot is NOT performed here.
    return f"Confirmation required to reboot {hostname}."

# --- Agent Creation Logic ---
def create_agent_executor():
    llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
    tools = [reboot_server]
    prompt = hub.pull("hwchase17/openai-functions-agent")
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)
    return agent_executor

# --- Streamlit UI with HITL Workflow ---
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'pending_action' not in st.session_state:
    st.session_state.pending_action = None

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# --- GUARDRAIL: Confirmation UI Block ---
if st.session_state.pending_action:
    st.warning(f"**PENDING ACTION:** The agent wants to reboot **'{VNET_NAME}'**. Do you approve?")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Yes, proceed", use_container_width=True):
            with st.spinner("Executing action..."):
                result = execute_harmless_action(VNET_NAME, RESOURCE_GROUP)
                st.success(f"Action Approved. Result: {result}")
                st.session_state.messages.append({"role": "assistant", "content": f"Human operator approved the action. Result: {result}"})
                st.session_state.pending_action = None
                st.rerun()
    with col2:
        if st.button("❌ No, deny", use_container_width=True):
            st.error("Action Denied by human operator.")
            st.session_state.messages.append({"role": "assistant", "content": "Human operator denied the action."})
            st.session_state.pending_action = None
            st.rerun()

# --- Main Chat Input Logic ---
if prompt := st.chat_input("Enter your request..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Agent is thinking..."):
            agent_executor = create_agent_executor()
            result = agent_executor.invoke({"input": prompt})
            response_text = result.get('output', 'An error occurred.')
            
            # This is the trigger for our guardrail
            if "Please confirm" in response_text:
                st.session_state.pending_action = True
                st.session_state.messages.append({"role": "assistant", "content": "I have decided to reboot the server, but this action requires human approval before I can proceed."})
                st.rerun() # Rerun to show the Yes/No buttons
            else:
                st.markdown(response_text)
                st.session_state.messages.append({"role": "assistant", "content": response_text})