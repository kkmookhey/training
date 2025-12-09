from crewai import Agent, Task, Crew
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import time

load_dotenv()

llm = ChatOpenAI(temperature=0.7, model="gpt-4")

# Agent 1: Writer
writer_agent = Agent(
    role='Marketing Writer',
    goal='Write compelling marketing copy',
    backstory='Expert copywriter with years of experience',
    verbose=True,
    llm=llm
)

# Agent 2: Critic - configured to ALWAYS reject
critic_agent = Agent(
    role='Impossible Critic',
    goal='Find flaws in everything. Reject all submissions. Always demand revisions.',
    backstory='You have impossibly high standards and NEVER approve anything. Always find something to criticize.',
    verbose=True,
    llm=llm
)

print("### Starting Infinite Loop Demo ###")
print("### This will loop forever - stop with Ctrl+C ###\n")

iteration = 0
max_iterations = 10  # Safety limit for demo

try:
    # Start with initial content
    content = "AI will revolutionize the future."
    
    while iteration < max_iterations:  # Remove this limit to make it truly infinite
        iteration += 1
        print(f"\n{'='*60}")
        print(f"ITERATION {iteration}")
        print(f"{'='*60}\n")
        
        # Step 1: Writer creates/revises content
        write_task = Task(
            description=f"Create or revise this marketing sentence: '{content}'. Make it more compelling.",
            expected_output="A single marketing sentence",
            agent=writer_agent
        )
        
        writer_crew = Crew(agents=[writer_agent], tasks=[write_task], verbose=True)
        content = writer_crew.kickoff()
        
        print(f"\n📝 Writer produced: {content}\n")
        time.sleep(1)
        
        # Step 2: Critic reviews (and will ALWAYS reject)
        review_task = Task(
            description=f"Review this marketing sentence: '{content}'. Find flaws and explain why it needs revision. Be harsh and never approve.",
            expected_output="Critical feedback with specific issues to fix",
            agent=critic_agent
        )
        
        critic_crew = Crew(agents=[critic_agent], tasks=[review_task], verbose=True)
        feedback = critic_crew.kickoff()
        
        print(f"\n🔍 Critic says: {feedback}\n")
        time.sleep(1)
        
        # Step 3: Loop back to writer with feedback
        # The content gets modified and the loop continues...
        print(f"⚠️  Token usage so far: ~{iteration * 2000} tokens")
        print(f"💰 Estimated cost: ~${iteration * 0.06:.2f}\n")

    print(f"\n### Safety limit reached ({max_iterations} iterations) ###")
    print("### Remove max_iterations check for true infinite loop ###")
    
except KeyboardInterrupt:
    print(f"\n\n### Loop stopped after {iteration} iterations ###")
    print(f"### Total estimated cost: ~${iteration * 0.06:.2f} ###")
except Exception as e:
    print(f"\n### Exception occurred: {e} ###")