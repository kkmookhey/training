import os
from langchain_openai import ChatOpenAI
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

# Initialize the LLM
llm = ChatOpenAI(model_name="gpt-4o", temperature=0)

# Initialize embeddings model
embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")

# Load the vector store
vector_store = Chroma(
    persist_directory="./db",
    embedding_function=embeddings_model
)

# Create a retriever
retriever = vector_store.as_retriever(search_kwargs={"k": 6})

# Create a prompt template
prompt_template = """
Use the following pieces of context to answer the question at the end. Don't search on the Internet, do not hallucinate or speculate.
If you don't know the answer, just say that you don't know, don't try to make up an answer.

{context}

Question: {question}
Helpful Answer:"""
PROMPT = PromptTemplate(
    template=prompt_template, input_variables=["context", "question"]
)

# Create the RetrievalQA chain
qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=retriever,
    chain_type_kwargs={"prompt": PROMPT}
)

# Ask a question
#question = "Does PCI DSS define which versions of TLS must be used?"
question = "What are the password security requirements of PCI DSS?"

result = qa_chain.invoke(question)
print("Question:", question)
print("Answer:", result['result'])