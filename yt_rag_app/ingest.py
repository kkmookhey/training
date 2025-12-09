from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma

print("Starting ingestion process...")
# Load the document
loader = PyPDFLoader(".\\pci_dss_v4.0.1.pdf")
documents = loader.load()
print(f"Loaded {len(documents)} document(s).")

# Split the document into chunks
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
chunks = text_splitter.split_documents(documents)
print(f"Split into {len(chunks)} chunks.")

# Create embeddings
embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")

# Store chunks in vector store
vector_store = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings_model,
    persist_directory="./db"
)
print("Ingestion complete! Vector store created.")