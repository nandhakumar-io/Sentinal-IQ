"""
Intelligent Security Query Interface.

Design principle: the LLM is a *summarizer over retrieved facts*, never a
freehand source of security claims. Flow:

  1. Embed the user's natural-language question
  2. Retrieve top-k relevant vulnerabilities/assets from OpenSearch + pgvector
     (scoped to auth.tenant_id — never cross-tenant)
  3. Pass ONLY the retrieved records + question to the LLM
  4. LLM answers strictly from provided context, must cite CVE IDs it used

This keeps hallucination risk low: if retrieval finds nothing, the LLM is
instructed to say so rather than invent a CVE.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import AuthContext, get_current_auth
from app.modules.nlq.service import answer_query

router = APIRouter(prefix="/nlq", tags=["nlq"])


class NLQRequest(BaseModel):
    question: str


class NLQResponse(BaseModel):
    answer: str
    cited_cves: list[str]


@router.post("/query", response_model=NLQResponse)
async def query(req: NLQRequest, auth: AuthContext = Depends(get_current_auth)):
    return await answer_query(question=req.question, tenant_id=auth.tenant_id)
