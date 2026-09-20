from langchain_core.tools import tool


def retrieve_knowledge(vector_store, query, k=3):
    return vector_store.similarity_search(
        query,
        k=k,
    )


def create_knowledge_tool(vector_store):

    @tool
    def search_incident_knowledge(query: str) -> str:
        """Search Aegis operational knowledge for incident investigation guidance."""

        results = retrieve_knowledge(
            vector_store,
            query,
            k=3,
        )

        if not results:
            return "No relevant operational knowledge found."

        output = []

        for i, document in enumerate(results, start=1):
            output.append(
                f"RESULT {i}\n"
                f"SOURCE: {document.metadata.get('source')}\n"
                f"SECTION: {document.metadata.get('section')}\n"
                f"CONTENT:\n{document.page_content}"
            )

        return "\n\n".join(output)

    return search_incident_knowledge