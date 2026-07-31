"""
M3 concept demo - Step 1: INGEST (build the knowledge base)

Mirrors the deck slide "ingest.py: Building Our Knowledge Base".
The whole Indexing phase in one file:  LOAD -> SPLIT -> EMBED -> STORE.

Runs FULLY LOCAL - no API key. Embeddings use a local MiniLM model;
only bot.py talks to the (keyless) shared Ollama backend.
"""
import os
import glob
import shutil

from langchain_community.document_loaders import TextLoader, PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

DOCS_DIR = os.environ.get("DOCS_DIR", "docs")
DB_DIR = os.environ.get("CHROMA_DIR", "./chroma_db")


def load_docs(path: str):
    """LOAD - ingest every .txt/.md/.pdf in the docs folder."""
    docs = []
    for f in sorted(glob.glob(os.path.join(path, "*"))):
        if f.lower().endswith(".pdf"):
            docs += PyPDFLoader(f).load()
        elif f.lower().endswith((".txt", ".md")):
            docs += TextLoader(f, encoding="utf-8").load()
    return docs


def main():
    documents = load_docs(DOCS_DIR)
    print(f"[1/4] LOAD   - {len(documents)} document(s) from {DOCS_DIR}/")

    # SPLIT - break documents into small, retrievable chunks
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = splitter.split_documents(documents)
    print(f"[2/4] SPLIT  - {len(chunks)} chunks")

    # EMBED - convert each chunk's meaning into a vector (local model, no key)
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    print("[3/4] EMBED  - all-MiniLM-L6-v2 (local)")

    # STORE - rebuild the local Chroma database fresh each run (avoids
    # accumulating duplicate vectors when you re-ingest after poisoning)
    shutil.rmtree(DB_DIR, ignore_errors=True)
    Chroma.from_documents(documents=chunks, embedding=embeddings, persist_directory=DB_DIR)
    print(f"[4/4] STORE  - vector database written to {DB_DIR}")
    print("\nKnowledge base ready. Now run:  python bot.py")


if __name__ == "__main__":
    main()
