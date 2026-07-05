"""
Retrieval-augmented answer generation. This is intentionally a separable
service boundary — it can be extracted into its own deployment (own scaling,
own release cadence, swap LLM providers) without touching the registry.
"""
from app.core.config import settings


async def retrieve_context(question: str, tenant_id: str, top_k: int = 8) -> list[dict]:
    """
    TODO: embed `question`, query OpenSearch (full-text) + pgvector (semantic)
    filtered to tenant_id's assets/matches, return top_k vulnerability records.
    """
    raise NotImplementedError


async def answer_query(question: str, tenant_id: str) -> dict:
    context = await retrieve_context(question, tenant_id)

    if not context:
        return {"answer": "No matching vulnerabilities found in your registry for this query.", "cited_cves": []}

    # TODO: call LLM (settings.llm_model) with a system prompt instructing:
    # "Answer ONLY using the provided vulnerability records below. Cite CVE IDs.
    #  If the records don't answer the question, say so explicitly."
    raise NotImplementedError
