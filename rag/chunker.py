from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)


def chunk_documents(documents):
    markdown_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[
            ("#", "title"),
            ("##", "section"),
        ],
        strip_headers=True,
    )

    recursive_splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=120,
        separators=["\n\n", "\n", ". ", " ", ""],
    )

    chunks = []

    for document in documents:
        sections = markdown_splitter.split_text(document["content"])

        for section in sections:
            section_chunks = recursive_splitter.split_documents([section])

            for chunk in section_chunks:
                chunk.metadata["source"] = document["source"]
                chunks.append(chunk)

    return chunks