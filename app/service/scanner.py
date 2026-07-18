from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path

import asyncpg

logger = logging.getLogger(__name__)


async def process_scan(db: asyncpg.Pool, payload: dict) -> None:
    scan_id = payload.get("scan_id")
    tenant_id = payload.get("tenant_id")
    target = payload.get("target")

    if not target or not tenant_id:
        logger.warning("missing target or tenant_id")
        return

    targets = await _wait_for_assets(db, tenant_id, target)
    if not targets:
        logger.info("no assets found for target %s after waiting", target)
        if scan_id:
            await _finish(db, scan_id, 0)
        return

    logger.info("running nuclei against %d targets for %s", len(targets), target)
    findings = await asyncio.get_event_loop().run_in_executor(
        None, _run_nuclei, targets
    )
    logger.info("nuclei found %d findings for %s", len(findings), target)

    total = 0
    for f in findings:
        stored = await _store_finding(db, tenant_id, scan_id, f)
        if stored:
            total += 1

    logger.info("stored %d findings for target %s", total, target)
    if scan_id:
        await _finish(db, scan_id, total)


async def _wait_for_assets(
    db: asyncpg.Pool, tenant_id: str, target: str, retries: int = 18, delay: int = 10
) -> list[str]:
    for attempt in range(retries):
        rows = await db.fetch(
            """
            SELECT DISTINCT ip::text
            FROM assets
            WHERE tenant_id = $1
            """,
            tenant_id,
        )
        if rows:
            return [r["ip"] for r in rows]
        logger.info("waiting for assets (attempt %d/%d)", attempt + 1, retries)
        await asyncio.sleep(delay)
    return []


def _run_nuclei(ips: list[str]) -> list[dict]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(ips))
        targets_file = tf.name

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as of:
        out_file = of.name

    try:
        subprocess.run(
            [
                "nuclei",
                "-l", targets_file,
                "-json-export", out_file,
                "-severity", "low,medium,high,critical",
                "-stats",
                "-silent",
                "-nc",
            ],
            capture_output=True,
            timeout=3600,
            check=False,
        )
        results = []
        for line in Path(out_file).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                keys = list(parsed.keys()) if isinstance(parsed, dict) else parsed
                logger.debug("nuclei result type=%s keys=%s", type(parsed).__name__, keys)
                results.append(parsed)
            except json.JSONDecodeError:
                continue
        return results
    except Exception as exc:
        logger.error("nuclei failed: %s", exc)
        return []
    finally:
        Path(targets_file).unlink(missing_ok=True)
        Path(out_file).unlink(missing_ok=True)


async def _store_finding(db: asyncpg.Pool, tenant_id: str, scan_id: str | None, f: dict) -> bool:
    try:
        if not isinstance(f, dict):
            logger.warning("unexpected finding type %s: %r", type(f).__name__, f)
            return False
        template_id = f.get("template-id", "unknown")
        info = f.get("info", {})
        if not isinstance(info, dict):
            info = {}
        name = info.get("name", template_id)
        severity = info.get("severity", "info").lower()
        description = info.get("description", "")
        cve_id = _extract_cve(f)
        host = f.get("host", "")
        ip = f.get("ip", "") or host

        asset_row = await db.fetchrow(
            "SELECT id FROM assets WHERE tenant_id = $1 AND ip::text = $2",
            tenant_id,
            ip,
        ) if ip else None
        asset_id = str(asset_row["id"]) if asset_row else None

        cve_uuid = await _upsert_cve(db, cve_id or template_id, name, severity, description)

        await db.execute(
            """
            INSERT INTO findings
                (tenant_id, asset_id, scan_job_id, cve_id, name, severity, status, matcher_name)
            VALUES ($1, $2, $3, $4, $5, $6::severity_level, 'open', $7)
            ON CONFLICT DO NOTHING
            """,
            tenant_id,
            asset_id,
            scan_id,
            cve_uuid,
            name,
            _map_severity(severity),
            template_id,
        )
        return True
    except Exception as exc:
        logger.warning("finding store failed: %s", exc)
        return False


def _extract_cve(f: dict) -> str | None:
    info = f.get("info", {})
    if not isinstance(info, dict):
        return None
    classification = info.get("classification", {})
    if not isinstance(classification, dict):
        return None
    for ref in classification.get("cve-id", []):
        if isinstance(ref, str) and ref.upper().startswith("CVE-"):
            return ref.upper()
    return None


def _map_severity(s: str) -> str:
    return s if s in ("low", "medium", "high", "critical") else "low"


async def _upsert_cve(
    db: asyncpg.Pool, cve_id: str, name: str, severity: str, description: str
) -> str | None:
    try:
        row = await db.fetchrow(
            """
            INSERT INTO cves (cve_id, description, severity)
            VALUES ($1, $2, $3::severity_level)
            ON CONFLICT (cve_id) DO UPDATE
                SET description = EXCLUDED.description,
                    severity = EXCLUDED.severity,
                    enriched_at = NOW()
            RETURNING id
            """,
            cve_id,
            description or name,
            _map_severity(severity),
        )
        return str(row["id"]) if row else None
    except Exception as exc:
        logger.warning("cve upsert failed %s: %s", cve_id, exc)
        return None


async def _finish(db: asyncpg.Pool, scan_id: str, findings: int) -> None:
    await db.execute(
        """
        UPDATE scan_jobs
        SET findings_found = $1, status = 'completed', completed_at = NOW()
        WHERE id = $2
        """,
        findings,
        scan_id,
    )
