"""LLM Analyst API: ask question, explain alert."""

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from psycopg.rows import dict_row

from unetdefence.llm import get_llm_analyst
from unetdefence.storage import get_pool, is_sqlite

router = APIRouter()


class QuestionRequest(BaseModel):
    question: str


class QuestionResponse(BaseModel):
    answer: str


class ExplainAlertRequest(BaseModel):
    alert_id: UUID


class ExplainAlertResponse(BaseModel):
    explanation: str


@router.post("/ask", response_model=QuestionResponse)
async def ask_question(req: QuestionRequest) -> QuestionResponse:
    """Answer a natural-language question using DB context and optional vector search."""
    pool = get_pool()
    context_parts = []
    if is_sqlite():
        sql_flows = "SELECT dst_country_code, COUNT(*) AS cnt FROM flows WHERE ts > datetime('now', '-24 hours') GROUP BY dst_country_code ORDER BY cnt DESC LIMIT 10"
        sql_alerts = "SELECT signature, severity FROM alerts WHERE ts > datetime('now', '-24 hours') ORDER BY ts DESC LIMIT 10"
    else:
        sql_flows = "SELECT dst_country_code, COUNT(*) AS cnt FROM flows WHERE ts > now() - interval '24 hours' GROUP BY dst_country_code ORDER BY cnt DESC LIMIT 10"
        sql_alerts = "SELECT signature, severity FROM alerts WHERE ts > now() - interval '24 hours' ORDER BY ts DESC LIMIT 10"
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(sql_flows)
            rows = await cur.fetchall()
            context_parts.append("Top destination countries (24h): " + ", ".join(f"{r['dst_country_code']}({r['cnt']})" for r in rows))
            await cur.execute(sql_alerts)
            rows = await cur.fetchall()
            context_parts.append("Recent alerts: " + "; ".join(f"{r['signature']}({r['severity']})" for r in rows))
    context = "\n".join(context_parts) or "No recent data."
    try:
        analyst = get_llm_analyst()
        answer = await analyst.generate_answer(req.question, context)
    except HTTPException:
        raise
    except Exception as e:
        detail = f"LLM unavailable or error: {e!s}"
        if "404" in str(e) or "Connection" in str(e):
            detail += " If the API runs in Docker, set UNETDEFENCE_LLM_BASE_URL=http://host.docker.internal:11434 to reach Ollama on the host."
        raise HTTPException(status_code=503, detail=detail)
    return QuestionResponse(answer=answer)


@router.post("/explain-alert", response_model=ExplainAlertResponse)
async def explain_alert(req: ExplainAlertRequest) -> ExplainAlertResponse:
    """Get LLM explanation for why an alert might be suspicious."""
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT ts, device_id, src_ip, dst_ip, signature, category, severity FROM alerts WHERE id = %s",
                (str(req.alert_id) if is_sqlite() else req.alert_id,),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert_summary = f"Alert: {row['signature']} | Severity: {row['severity']} | {row['ts']} | src={row['src_ip']} dst={row['dst_ip']}"
    related = f"Device id: {row['device_id']}. No additional context loaded."
    try:
        analyst = get_llm_analyst()
        explanation = await analyst.explain_alert(alert_summary, related)
    except HTTPException:
        raise
    except Exception as e:
        detail = f"LLM unavailable or error: {e!s}"
        if "404" in str(e) or "Connection" in str(e):
            detail += " If Docker: UNETDEFENCE_LLM_BASE_URL=http://host.docker.internal:11434"
        raise HTTPException(status_code=503, detail=detail)
    return ExplainAlertResponse(explanation=explanation)
