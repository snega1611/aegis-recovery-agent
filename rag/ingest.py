from rag.loader import load_incident_knowledge
from rag.chunker import chunk_documents
from rag.vectorstore import create_vector_store


knowledge = load_incident_knowledge()
chunks = chunk_documents(knowledge)

vector_store = create_vector_store(chunks)

print(f"✅ Indexed {len(chunks)} chunks into Chroma.")