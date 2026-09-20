from rag.vectorstore import load_vector_store
from rag.retriever import retrieve_knowledge


vector_store = load_vector_store()

query = """
The backend CPU is currently high but request traffic is normal.
What should an SRE investigate to determine the cause?
"""

results = retrieve_knowledge(
    vector_store,
    query,
    k=3,
)

print("\n🔎 RETRIEVED KNOWLEDGE:")

for i, document in enumerate(results, start=1):
    print(f"\n--- RESULT {i} ---")
    print("SOURCE:", document.metadata.get("source"))
    print("SECTION:", document.metadata.get("section"))
    print(document.page_content)