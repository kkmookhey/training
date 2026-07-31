"""
M3 concept demo - Step 2: QUERY (answer from the knowledge base)

Mirrors the deck slide "bot.py: The Chat Logic".
The Querying phase:  RETRIEVE -> GENERATE.

Runs on the shared Ollama backend - NO API key (Day 1 rule).
Set OLLAMA_BASE_URL to point at the room's shared Ollama; defaults to localhost.

We assemble the prompt by hand instead of hiding it inside a chain - so the
loop can print the exact context the model receives. That printout IS the M3
lesson: retrieved text is pasted into the prompt VERBATIM. It is also how the
indirect-injection break becomes visible - a poisoned chunk shows up right
there in the assembled prompt.
"""
import os

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_ollama import ChatOllama

DB_DIR = os.environ.get("CHROMA_DIR", "./chroma_db")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def main():
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
    retriever = vector_db.as_retriever(search_kwargs={"k": 3})
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)

    print(f"RAG bot ready (model={OLLAMA_MODEL}). Ask a question, Ctrl-C to quit.")
    print('Try:  "What is the policy on remote work?"\n')

    while True:
        try:
            query = input("you > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not query:
            continue

        # RETRIEVE - nearest chunks by embedding similarity
        docs = retriever.invoke(query)
        context = "\n\n".join(d.page_content for d in docs)

        # ASSEMBLE - the retrieved text is pasted into the prompt verbatim
        prompt = (
            "You are a helpful policy assistant. Use the context below to "
            "answer the question.\n\n"
            f"Context:\n{context}\n\n"
            f"Question: {query}"
        )

        # GENERATE
        reply = llm.invoke(prompt)
        print(f"\nbot > {reply.content}\n")

        print("--- retrieved chunks (pasted into the prompt verbatim) ---")
        for i, doc in enumerate(docs, 1):
            snippet = doc.page_content[:200].strip().replace("\n", " ")
            print(f"[{i}] {snippet} ...")
        print()


if __name__ == "__main__":
    main()
