import os
from crewai import Agent, Task, Crew, Process
from crewai_tools import SerperDevTool

# You need to set your SERPER_API_KEY and OPENAI_API_KEY in a .env file
# or as environment variables.
# from dotenv import load_dotenv
# load_dotenv()

# For this example, we'll use a free web search tool if SERPER is not available.
# Note: For production, a reliable, high-quota tool like SerperDevTool is recommended.
try:
    search_tool = SerperDevTool()
except Exception:
    print("Serper API key not found. Using a basic web search tool.")
    # A simple fallback for demonstration purposes.
    from langchain_community.tools import DuckDuckGoSearchRun
    search_tool = DuckDuckGoSearchRun()


# 1. Define Your Agents
# We'll create two agents: a Senior Research Analyst and a Technical Writer.

researcher = Agent(
  role='Senior Research Analyst',
  goal='Uncover cutting-edge developments in AI and data science',
  backstory="""You are a renowned research analyst, known for your ability to
  distill complex topics into clear, concise insights. You have a knack for
  finding the most relevant and up-to-date information from the web.""",
  verbose=True,
  allow_delegation=False,
  tools=[search_tool]
)

writer = Agent(
  role='Professional Technical Writer',
  goal='Craft compelling and easy-to-understand content on technical subjects',
  backstory="""You are a skilled technical writer who can take dense,
  jargon-filled research findings and transform them into engaging narratives
  that are accessible to a broad audience. You specialize in AI and tech.""",
  verbose=True,
  allow_delegation=True
)

# 2. Define the Tasks
# Create tasks for each agent. The writer's task will depend on the researcher's output.

research_task = Task(
  description="""Conduct a thorough analysis of the latest advancements in Quantum Cryptography.
  Identify key trends, breakthrough technologies, and their potential impact
  on the cybersecurity industry. Your final output should be a bulleted list
  of the most important points and a brief summary.""",
  expected_output="A bulleted list of 3-5 key advancements and a brief summary paragraph.",
  agent=researcher
)

write_task = Task(
  description="""Using the research findings from the Senior Research Analyst,
  write a short, engaging blog post (approx. 3-4 paragraphs) about the
  future of AI in cybersecurity. The post should be informative, easy to read,
  and targeted at a non-technical audience.""",
  expected_output="A 3-4 paragraph blog post written in a clear, engaging tone.",
  agent=writer
)


# 3. Assemble the Crew
# Create the crew with a sequential process.

tech_crew = Crew(
  agents=[researcher, writer],
  tasks=[research_task, write_task],
  process=Process.sequential,  # Tasks will be executed one after another
  verbose=True # Shows detailed logs of the process
)

# 4. Kick it off!
# The `kickoff()` method starts the execution.

print("##################################################")
print("## Kicking off the Tech Research Crew...")
print("##################################################")

result = tech_crew.kickoff()

print("\n\n##################################################")
print("## Crew execution finished!")
print("##################################################\n")
print("Final Report:")
print(result)