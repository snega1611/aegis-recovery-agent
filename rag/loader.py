from pathlib import Path


def load_incident_knowledge():
    knowledge_dir = Path("incidents")

    documents = []

    for file_path in knowledge_dir.glob("*.md"):
        documents.append(
            {
                "source": file_path.name,
                "content": file_path.read_text(encoding="utf-8"),
            }
        )

    return documents