from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings


EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

VECTOR_STORE_PATH = "data/vector_store"
COLLECTION_NAME = "aegis_incident_knowledge"


def _get_vector_store():
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL
    )

    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=embeddings,
        persist_directory=VECTOR_STORE_PATH,
    )


def create_vector_store(chunks):
    vector_store = _get_vector_store()
    vector_store.add_documents(chunks)
    return vector_store


def load_vector_store():
    return _get_vector_store()