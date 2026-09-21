from pathlib import Path


def load_incident_knowledge():
    knowledge_dirs = [
        Path("incidents"),
        Path("sre"),
    ]

    documents = []

    for knowledge_dir in knowledge_dirs:
        for file_path in knowledge_dir.glob("*.md"):
            documents.append(
                {
                    "source": str(file_path),
                    "content": file_path.read_text(encoding="utf-8"),
                }
            )

    return documents