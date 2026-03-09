"""LLM Analyst API: ask question, explain alert."""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from psycopg.rows import dict_row

from unetdefence.llm import get_llm_analyst
from unetdefence.config import get_settings
from unetdefence.storage import get_pool, is_sqlite

router = APIRouter()


def _utc_now() -> datetime:
    """UTC timestamp used for time-bounded context queries."""
    return datetime.utcnow()


class QuestionRequest(BaseModel):
    question: str
    since_hours: int | None = None
    include_domains: bool = False
    include_tls_sni: bool = False
    include_dst_ips: bool = False
    language: str | None = None


class QuestionResponse(BaseModel):
    answer: str
    full_prompt: str | None = None
    llm_model: str | None = None


class ExplainAlertRequest(BaseModel):
    alert_id: UUID


class ExplainAlertResponse(BaseModel):
    explanation: str


@router.post("/ask", response_model=QuestionResponse)
async def ask_question(req: QuestionRequest) -> QuestionResponse:
    """Answer a natural-language question using DB context and optional vector search."""
    pool = get_pool()
    context_parts = []
    # 1) Baseline context: top destination countries and recent alerts (24h, existing behaviour)
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
            context_parts.append(
                "Top destination countries (24h): "
                + ", ".join(f"{r['dst_country_code']}({r['cnt']})" for r in rows)
            )
            await cur.execute(sql_alerts)
            rows = await cur.fetchall()
            context_parts.append(
                "Recent alerts (24h): "
                + "; ".join(f"{r['signature']}({r['severity']})" for r in rows)
            )

            # 2) Optional detailed context for domains / TLS-SNI / destination IPs (time-bounded)
            since_hours = req.since_hours or 24
            if req.include_domains:
                since = _utc_now() - timedelta(hours=since_hours)
                await cur.execute(
                    """
                    SELECT domain, COUNT(*) AS cnt
                    FROM (
                        SELECT query AS domain
                        FROM dns_events
                        WHERE ts >= %s AND query IS NOT NULL AND query != ''
                        UNION ALL
                        SELECT host AS domain
                        FROM http_events
                        WHERE ts >= %s AND host IS NOT NULL AND host != ''
                        UNION ALL
                        SELECT sni AS domain
                        FROM tls_events
                        WHERE ts >= %s AND sni IS NOT NULL AND sni != ''
                    ) d
                    GROUP BY domain
                    ORDER BY cnt DESC, domain
                    LIMIT 200
                    """,
                    (since, since, since),
                )
                rows = await cur.fetchall()
                if rows:
                    context_parts.append(
                        f"Domains observed in the last {since_hours}h: "
                        + ", ".join(f"{r['domain']}({r['cnt']})" for r in rows)
                    )

            if req.include_tls_sni:
                since = _utc_now() - timedelta(hours=since_hours)
                await cur.execute(
                    """
                    SELECT sni, COUNT(*) AS tls_count
                    FROM tls_events
                    WHERE ts >= %s AND sni IS NOT NULL AND sni != ''
                    GROUP BY sni
                    ORDER BY tls_count DESC, sni
                    LIMIT 200
                    """,
                    (since,),
                )
                rows = await cur.fetchall()
                if rows:
                    context_parts.append(
                        f"TLS SNI names in the last {since_hours}h: "
                        + ", ".join(f"{r['sni']}({r['tls_count']})" for r in rows)
                    )

            if req.include_dst_ips:
                since = _utc_now() - timedelta(hours=since_hours)
                await cur.execute(
                    """
                    SELECT dst_ip AS ip, COUNT(*) AS flow_count
                    FROM flows
                    WHERE ts >= %s
                    GROUP BY dst_ip
                    ORDER BY flow_count DESC, ip
                    LIMIT 200
                    """,
                    (since,),
                )
                rows = await cur.fetchall()
                if rows:
                    context_parts.append(
                        f"Destination IPs in the last {since_hours}h: "
                        + ", ".join(f"{r['ip']}({r['flow_count']})" for r in rows)
                    )
    context = "\n".join(context_parts) or "No recent data."
    try:
        analyst = get_llm_analyst()
        # Optional language hint for the LLM
        question_text = req.question
        if req.language:
            lang = req.language.strip()
            if lang:
                question_text = f"Please answer in {lang}. Original question: {req.question}"
        answer, full_prompt = await analyst.generate_answer(question_text, context)
    except HTTPException:
        raise
    except Exception as e:
        detail = f"LLM unavailable or error: {e!s}"
        if "404" in str(e) or "Connection" in str(e):
            detail += " If the API runs in Docker, set UNETDEFENCE_LLM_BASE_URL=http://host.docker.internal:11434 to reach Ollama on the host."
        raise HTTPException(status_code=503, detail=detail)
    settings = get_settings()
    model_name = settings.llm.model
    return QuestionResponse(answer=answer, full_prompt=full_prompt, llm_model=model_name)


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
