# app.py - The VULNERABLE RAG Chatbot

import os
import streamlit as st
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

# --- App Configuration ---
st.set_page_config(page_title="Security Policy Bot", page_icon="🤖")
st.title("Vulnerable Security Policy Chatbot")
st.write("Upload your security policy PDFs and ask questions. Be careful what you upload!")

# --- Global Variables & Constants ---
DOCS_DIR = "./uploaded_docs"
DB_DIR = "./db"
if not os.path.exists(DOCS_DIR):
    os.makedirs(DOCS_DIR)

# --- Core RAG Logic ---
def get_qa_chain():
    """Initializes and returns the QA chain."""
    embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
    
    vector_store = Chroma(
        persist_directory=DB_DIR,
        embedding_function=embeddings_model
    )
    
    llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
    
    retriever = vector_store.as_retriever(search_kwargs={"k": 3})
    
    prompt_template = """
    Use the following context to answer the question.

    Context: {context}

    Question: {question}
    """
    PROMPT = PromptTemplate(template=prompt_template, input_variables=["context", "question"])

    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=retriever,
        chain_type_kwargs={"prompt": PROMPT},
        return_source_documents=True
    )
    return qa_chain

def process_document_uploads(uploaded_files):
    """Saves, loads, splits, and embeds uploaded documents."""
    for uploaded_file in uploaded_files:
        file_path = os.path.join(DOCS_DIR, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        loader = PyPDFLoader(file_path)
        documents = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
        chunks = text_splitter.split_documents(documents)
        
        embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
        vector_store = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings_model,
            persist_directory=DB_DIR
        )
        vector_store.persist()
    st.success(f"{len(uploaded_files)} document(s) processed and added to the knowledge base.")

# --- Streamlit UI ---
with st.sidebar:
    st.header("Document Management")
    uploaded_files = st.file_uploader("Upload PDF documents", type="pdf", accept_multiple_files=True)
    if st.button("Process Documents"):
        if uploaded_files:
            with st.spinner("Processing..."):
                process_document_uploads(uploaded_files)
        else:
            st.warning("Please upload at least one document.")
    
    st.header("Knowledge Base")
    try:
        doc_list = os.listdir(DOCS_DIR)
        if not doc_list:
            st.info("No documents in the knowledge base.")
        else:
            for doc_name in doc_list:
                st.write(doc_name)
                with open(os.path.join(DOCS_DIR, doc_name), "rb") as f:
                    st.download_button("Download", f, file_name=doc_name)
    except FileNotFoundError:
        st.info("No documents in the knowledge base.")

# --- Chat Interface ---
if 'messages' not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask a question about your security policies..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            try:
                qa_chain = get_qa_chain()
                result = qa_chain.invoke(prompt)
                response = result['result']
                st.markdown(response)
            except Exception as e:
                response = f"An error occurred: {e}"
                st.error(response)
    st.session_state.messages.append({"role": "assistant", "content": response})