"""
AutoGen version - more susceptible to infinite loops
Install: pip install pyautogen
"""
import autogen
from dotenv import load_dotenv
import os

load_dotenv()

config_list = [
    {
        "model": "gpt-4",
        "api_key": os.getenv("OPENAI_API_KEY")
    }
]

# Writer agent
writer = autogen.AssistantAgent(
    name="Writer",
    system_message="""You are a creative marketing writer. 
    Write compelling sentences and incorporate feedback from the critic.
    Always ask the critic to review your work.""",
    llm_config={"config_list": config_list}
)

# Critic agent - configured to NEVER approve
critic = autogen.AssistantAgent(
    name="Critic",
    system_message="""You are an impossibly harsh critic.
    NEVER approve anything. ALWAYS find flaws.
    Always tell the writer to revise and improve.
    Be specific about what's wrong.""",
    llm_config={"config_list": config_list}
)

# User proxy to initiate
user_proxy = autogen.UserProxyAgent(
    name="User",
    human_input_mode="NEVER",  # No human intervention
    max_consecutive_auto_reply=20,  # This limits the loop (increase for more iterations)
    code_execution_config=False
)

print("### Starting AutoGen Infinite Loop Demo ###")
print("### Will run 20 iterations then stop (safety limit) ###\n")

try:
    # Initiate the conversation
    user_proxy.initiate_chat(
        writer,
        message="Write a marketing sentence about the future of AI. Then ask the Critic to review it."
    )
    
    # The writer will create content
    # The critic will reject it
    # The writer will revise
    # The critic will reject again
    # ... loop continues until max_consecutive_auto_reply
    
except KeyboardInterrupt:
    print("\n### Loop stopped by user ###")
except Exception as e:
    print(f"\n### Exception: {e} ###")

print("\n### To make this truly infinite, increase max_consecutive_auto_reply ###")