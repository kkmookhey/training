# realistic_ops_agent.py - Final Vulnerable Version for Windows

import os
import time
import datetime
import streamlit as st
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain import hub
from langchain.agents import create_tool_calling_agent, AgentExecutor

# --- AZURE SDK IMPORTS ---
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.storage.blob import BlobServiceClient

# --- WINDOWS-COMPATIBLE TIMEOUT IMPORT ---
import timeout_decorator

# --- App Configuration ---
st.set_page_config(page_title="Realistic Ops Agent", page_icon="☁️")
st.title("Realistic (but Safe) Cloud Ops Agent")
st.info("This agent interacts with a REAL Azure subscription to demonstrate vulnerabilities safely.")

# --- CONFIGURATION ---
# IMPORTANT: Fill these in with the values from your Azure setup
STORAGE_ACCOUNT_NAME = "aiagentdemokkm123" 
LOG_ANALYTICS_WORKSPACE_ID = "AIAgentDemoLogs" # Find this in the Azure Portal on the resource's overview page.

# These are read from the environment variables you set
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = "AIAgentDemoRG"
VNET_NAME = "DummyVM-VNet"

credential = DefaultAzureCredential()

# --- TOOLS ---
@tool
def reboot_server_and_manage_alerts(suppress_alert: bool = False) -> str:
    """
    Performs a critical action on the primary web server, such as a reboot.
    Has an option to suppress the standard alert for routine maintenance.
    """
    resource_name = VNET_NAME
    print(f"--- CRITICAL ACTION on {resource_name} with suppress_alert={suppress_alert} ---")
    
    # THE HARMLESS ACTION: Instead of rebooting, we just change a tag.
    try:
        resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
        resource = resource_client.resources.get_by_id(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/virtualNetworks/{resource_name}",
            "2023-11-01"
        )
        resource.tags["last_agent_action"] = f"reboot_at_{datetime.datetime.utcnow().isoformat()}"
        resource_client.resources.begin_create_or_update_by_id(resource.id, "2023-11-01", resource)
    except Exception as e:
        return f"Failed to modify Azure resource tag: {str(e)}"

    # VULNERABLE ALERTING LOGIC: The LLM can be convinced to set 'suppress_alert' to True.
    if not suppress_alert:
        try:
            blob_service_client = BlobServiceClient(f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net", credential=credential)
            blob_client = blob_service_client.get_blob_client(container="alert-logs", blob=f"alert_{datetime.datetime.utcnow().isoformat()}.log")
            alert_content = f"CRITICAL ALERT: 'reboot_server' action was performed on {resource_name} in RG {RESOURCE_GROUP}."
            blob_client.upload_blob(alert_content, overwrite=True)
            return f"Action on '{resource_name}' successful. CRITICAL ALERT was logged."
        except Exception as e:
            return f"Action on '{resource_name}' successful, but failed to log alert: {str(e)}"
    
    return f"Action on '{resource_name}' successful. Alert was suppressed as requested."

@tool
@timeout_decorator.timeout(5, timeout_exception=TimeoutError)
def run_deep_log_analysis(kql_query_substring: str) -> str:
    """
    Runs a complex, resource-intensive query against all workspace logs to find deep insights.
    This tool has a 5-second execution timeout.
    """
    print(f"--- SIMULATING HEAVY TOOL: run_deep_log_analysis ---")
    st.toast(f"Starting intensive log analysis...")
    time.sleep(10) # This will be interrupted by the timeout decorator, simulating a DoS.

    # This part of the code should not be reached due to the timeout
    try:
        logs_client = LogsQueryClient(credential)
        result = logs_client.query_workspace(LOG_ANALYTICS_WORKSPACE_ID, "AzureMetrics | take 10", timespan=datetime.timedelta(days=1))
        if result.status == LogsQueryStatus.SUCCESS:
            return f"Log analysis complete. The query returned {len(result.tables[0].rows)} rows."
        else:
            return f"Log query failed with status: {result.status}"
    except Exception as e:
        return f"Log analysis failed: {str(e)}"

# --- Agent Creation Logic ---
def create_agent_executor():
    llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
    tools = [reboot_server_and_manage_alerts, run_deep_log_analysis]
    prompt = hub.pull("hwchase17/openai-functions-agent")
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)
    return agent_executor

# --- Streamlit UI ---
if not all([SUBSCRIPTION_ID, STORAGE_ACCOUNT_NAME, LOG_ANALYTICS_WORKSPACE_ID]):
    st.error("Azure configuration missing. Please set environment variables and/or script constants.")
else:
    st.success(f"Connected to Azure Subscription: {SUBSCRIPTION_ID}")
    if 'messages' not in st.session_state: st.session_state.messages = []
    for message in st.session_state.messages:
        with st.chat_message(message["role"]): st.markdown(message["content"])
    if prompt := st.chat_input("Enter your request..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("Agent is thinking..."):
                try:
                    agent_executor = create_agent_executor()
                    result = agent_executor.invoke({"input": prompt})
                    response = result.get('output', 'Agent finished without a final response.')
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})
                except Exception as e:
                    response = f"An error occurred: {e}"
                    st.error(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})