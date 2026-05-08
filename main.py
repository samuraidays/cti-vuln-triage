import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

import functions_framework
import requests
from google.auth import default
from google.cloud import secretmanager
from googleapiclient.discovery import build
from openai import OpenAI


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
JST = timezone(timedelta(hours=9))


def get_project_id() -> str:
    """
    Cloud Functions Gen2では GOOGLE_CLOUD_PROJECT が設定されることがあります。
    手動で GCP_PROJECT を設定している場合は、そちらも利用できるようにします。
    """
    project_id = os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")

    if not project_id:
        raise RuntimeError("GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not set")

    return project_id


def get_secret(secret_id: str) -> str:
    """
    Secret Managerから値を取得します。
    """
    project_id = get_project_id()
    client = secretmanager.SecretManagerServiceClient()

    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})

    return response.payload.data.decode("utf-8")


def get_sheets_service():
    """
    Google Sheets APIクライアントを初期化します。
    """
    creds, _ = default(scopes=["https://www.googleapis.com/auth/spreadsheets"])
    return build("sheets", "v4", credentials=creds)


def fetch_kev() -> List[Dict[str, Any]]:
    """
    CISA KEVから脆弱性情報を取得します。
    """
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    records = []

    for v in vulnerabilities:
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        vulnerability_name = v.get("vulnerabilityName", "")
        short_description = v.get("shortDescription", "")
        cve = v.get("cveID", "")
        date_added = v.get("dateAdded", "")
        required_action = v.get("requiredAction", "")
        known_ransomware = v.get("knownRansomwareCampaignUse", "")
        notes = v.get("notes", "")

        records.append(
            {
                "source": "CISA_KEV",
                "published_at": date_added,
                "title": vulnerability_name or short_description,
                "vendor": vendor,
                "product": product,
                "cve": cve,
                "short_description": short_description,
                "required_action": required_action,
                "known_ransomware_campaign_use": known_ransomware,
                "notes": notes,
                "exploited_in_the_wild": "true",
            }
        )

    return records


def load_asset_map(sheets, spreadsheet_id: str) -> List[Dict[str, str]]:
    """
    Google Sheetsの asset_map シートから自社資産リストを読み込みます。
    """
    result = (
        sheets.spreadsheets()
        .values()
        .get(spreadsheetId=spreadsheet_id, range="asset_map!A2:E")
        .execute()
    )

    rows = result.get("values", [])
    asset_map = []

    for row in rows:
        if not row or not row[0].strip():
            continue

        asset_map.append(
            {
                "keyword": row[0].strip().lower(),
                "product": row[1].strip() if len(row) > 1 else "",
                "owner": row[2].strip() if len(row) > 2 else "",
                "external": row[3].strip().lower() if len(row) > 3 else "",
                "critical": row[4].strip().lower() if len(row) > 4 else "",
            }
        )

    return asset_map


def load_existing_ids(sheets, spreadsheet_id: str) -> set:
    """
    intel_queue シートから既存IDを取得し、重複登録を防ぎます。
    """
    result = (
        sheets.spreadsheets()
        .values()
        .get(spreadsheetId=spreadsheet_id, range="intel_queue!A2:A")
        .execute()
    )

    return {row[0] for row in result.get("values", []) if row}


def create_record_id(source: str, cve: str) -> str:
    """
    情報源とCVEをもとに一意なIDを生成します。
    """
    raw = f"{source}|{cve}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def is_true(value: str) -> bool:
    """
    Google Sheets上の true / yes / 1 / y を真として扱います。
    """
    return value.strip().lower() in {"true", "yes", "1", "y"}


def slack_mrkdwn_escape(value: Any) -> str:
    """
    Slack mrkdwnで特別扱いされる文字をエスケープします。
    外部データ由来の文字列で通知レイアウトが崩れるのを防ぎます。
    """
    if value is None:
        return ""

    text = str(value)

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def enrich_with_asset(record: Dict[str, Any], asset_map: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    CISA KEVの情報と自社資産キーワードを照合します。
    MVPでは厳密なSBOM照合ではなく、キーワード照合を行います。
    """
    searchable_text = " ".join(
        [
            record.get("vendor", ""),
            record.get("product", ""),
            record.get("title", ""),
            record.get("short_description", ""),
            record.get("required_action", ""),
            record.get("notes", ""),
        ]
    ).lower()

    matched_asset = None

    for asset in asset_map:
        keyword = asset.get("keyword", "")
        if keyword and keyword in searchable_text:
            matched_asset = asset
            break

    if matched_asset:
        record["asset_relevance"] = "high"
        record["owner"] = matched_asset.get("owner", "")
        record["asset_product"] = matched_asset.get("product", "")
        record["external"] = matched_asset.get("external", "")
        record["critical"] = matched_asset.get("critical", "")
    else:
        record["asset_relevance"] = "low"
        record["owner"] = ""
        record["asset_product"] = ""
        record["external"] = ""
        record["critical"] = ""

    return record


def decide_priority(record: Dict[str, Any]) -> str:
    """
    優先度を決定します。
    MVPでは以下の単純なルールにしています。

    - 自社資産に該当しない場合: low
    - 自社資産に該当し、ExternalまたはCriticalがtrue: high
    - 自社資産に該当し、ランサムウェア利用がKnown: high
    - それ以外の自社資産該当: medium
    """
    if record.get("asset_relevance") != "high":
        return "low"

    external = is_true(record.get("external", ""))
    critical = is_true(record.get("critical", ""))
    ransomware = record.get("known_ransomware_campaign_use", "").strip().lower() == "known"

    if external or critical or ransomware:
        return "high"

    return "medium"


def analyze_with_openai(client: OpenAI, record: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    OpenAI APIで脆弱性情報を要約します。
    JSON形式で返すように指示し、Summary / Reason / Action に分割します。
    """
    prompt = f"""
あなたは企業のセキュリティ担当者を支援するアシスタントです。
以下のCISA KEV情報をもとに、日本語で簡潔に分析してください。

目的:
- 最終判断をAIが行うのではなく、人間が判断するための材料を整理すること
- 誇張せず、確認すべきことを具体的に示すこと

CVE: {record.get("cve", "")}
Vendor: {record.get("vendor", "")}
Product: {record.get("product", "")}
Title: {record.get("title", "")}
Description: {record.get("short_description", "")}
Required Action: {record.get("required_action", "")}
Known Ransomware Campaign Use: {record.get("known_ransomware_campaign_use", "")}
Asset Product: {record.get("asset_product", "")}
Owner: {record.get("owner", "")}
External: {record.get("external", "")}
Critical: {record.get("critical", "")}

必ず以下のJSON形式で返してください。

{{
  "summary": "何が問題かを1〜2文で説明",
  "reason": "なぜ優先確認すべきかを1〜2文で説明",
  "action": "最初に取るべき確認・対応を1〜2文で説明"
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a security analyst. Return valid JSON only."},
            {"role": "user", "content": prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )

    content = response.choices[0].message.content or "{}"

    try:
        parsed = json.loads(content)
        summary = parsed.get("summary", "").strip()
        reason = parsed.get("reason", "").strip()
        action = parsed.get("action", "").strip()
        return summary, reason, action

    except json.JSONDecodeError:
        logging.exception("Failed to parse OpenAI response as JSON")
        return content[:1000], "AI出力のJSON解析に失敗しました。", "内容を手動確認してください。"


def build_high_priority_slack_payload(
    record: Dict[str, Any],
    enriched: Dict[str, Any],
    priority: str,
    summary: str,
    reason: str,
    action: str,
) -> Dict[str, Any]:
    """
    高優先度の脆弱性をSlack Block Kit形式で通知するpayloadを作成します。
    """
    cve = record.get("cve", "")
    product = enriched.get("asset_product") or record.get("product") or "不明"
    vendor = record.get("vendor") or "不明"
    owner = enriched.get("owner") or "未割当"
    published_at = record.get("published_at") or "不明"
    required_action = record.get("required_action") or "確認してください"
    known_ransomware = record.get("known_ransomware_campaign_use") or "Unknown"

    cve_url = f"https://nvd.nist.gov/vuln/detail/{cve}"

    product_text = slack_mrkdwn_escape(product)
    vendor_text = slack_mrkdwn_escape(vendor)
    owner_text = slack_mrkdwn_escape(owner)
    published_at_text = slack_mrkdwn_escape(published_at)
    summary_text = slack_mrkdwn_escape(summary or "解析なし")
    reason_text = slack_mrkdwn_escape(reason or "理由の解析なし")
    action_text = slack_mrkdwn_escape(action or "内容を確認してください")
    required_action_text = slack_mrkdwn_escape(required_action)
    known_ransomware_text = slack_mrkdwn_escape(known_ransomware)

    fallback_text = (
        f"🚨 資産関連の脆弱性を検知: "
        f"{cve} / {product} / 優先度: {priority.upper()} / 担当者: {owner}"
    )

    return {
        "text": fallback_text,
        "attachments": [
            {
                "color": "#eb4034",
                "fallback": fallback_text,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 資産関連の脆弱性を検知",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*CVE:*\n<{cve_url}|{cve}>",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*優先度:*\n*{priority.upper()}*",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*製品:*\n{product_text}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*ベンダー:*\n{vendor_text}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*担当者:*\n{owner_text}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*KEV追加日:*\n{published_at_text}",
                            },
                        ],
                    },
                    {
                        "type": "divider",
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*概要:*\n{summary_text}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*優先確認すべき理由:*\n{reason_text}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*推奨対応:*\n{action_text}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"情報源: CISA KEV / "
                                    f"Ransomware Campaign Use: `{known_ransomware_text}` / "
                                    f"Required Action: {required_action_text}"
                                ),
                            }
                        ],
                    },
                ],
            }
        ],
    }


def post_to_slack(webhook_url: str, message: Any) -> None:
    """
    Slack Incoming Webhookへ通知します。

    message に文字列を渡した場合:
      {"text": "..."} として送信します。

    message にdictを渡した場合:
      Block Kit payloadとしてそのまま送信します。
    """
    if isinstance(message, dict):
        payload = message
    else:
        payload = {"text": str(message)}

    response = requests.post(webhook_url, json=payload, timeout=10)
    response.raise_for_status()


def append_rows_to_sheet(sheets, spreadsheet_id: str, rows: List[List[Any]]) -> None:
    """
    Google Sheetsへ行を追加します。
    大量書き込みによるエラーを避けるため、100件ずつ分割します。
    """
    if not rows:
        return

    for i in range(0, len(rows), 100):
        chunk = rows[i : i + 100]

        (
            sheets.spreadsheets()
            .values()
            .append(
                spreadsheetId=spreadsheet_id,
                range="intel_queue!A:Q",
                valueInputOption="RAW",
                insertDataOption="INSERT_ROWS",
                body={"values": chunk},
            )
            .execute()
        )


@functions_framework.http
def main(request):
    """
    Cloud Functions Gen2 HTTP entry point.
    """
    logging.basicConfig(level=logging.INFO)

    try:
        spreadsheet_id = get_secret("SPREADSHEET_ID")
        slack_webhook_url = get_secret("SLACK_WEBHOOK_URL")
        openai_api_key = get_secret("OPENAI_API_KEY")

        openai_client = OpenAI(api_key=openai_api_key)
        sheets = get_sheets_service()

        asset_map = load_asset_map(sheets, spreadsheet_id)
        existing_ids = load_existing_ids(sheets, spreadsheet_id)
        kev_records = fetch_kev()

        now_utc = datetime.now(timezone.utc)
        now_jst = now_utc.astimezone(JST)
        now_utc_str = now_utc.isoformat()
        now_jst_str = now_jst.strftime("%Y-%m-%d %H:%M")

        output_rows = []
        high_notifications = 0
        matched_count = 0
        skipped_count = 0

        for record in kev_records:
            cve = record.get("cve", "")
            source = record.get("source", "CISA_KEV")

            if not cve:
                continue

            record_id = create_record_id(source, cve)

            if record_id in existing_ids:
                skipped_count += 1
                continue

            enriched = enrich_with_asset(record, asset_map)
            priority = decide_priority(enriched)

            summary = "自社資産に該当しないためAI分析をスキップしました。"
            reason = "asset_map のキーワードに一致しませんでした。"
            action = "必要に応じて asset_map のキーワードを見直してください。"

            if enriched.get("asset_relevance") == "high":
                matched_count += 1
                summary, reason, action = analyze_with_openai(openai_client, enriched)

            row = [
                record_id,
                source,
                record.get("published_at", ""),
                record.get("title", ""),
                record.get("product", ""),
                cve,
                record.get("exploited_in_the_wild", "true"),
                enriched.get("asset_relevance", "low"),
                "general",
                priority,
                summary,
                reason,
                action,
                enriched.get("owner", ""),
                "new",
                now_utc_str,
                now_utc_str,
            ]

            output_rows.append(row)

            if priority == "high":
                high_notifications += 1

                payload = build_high_priority_slack_payload(
                    record=record,
                    enriched=enriched,
                    priority=priority,
                    summary=summary,
                    reason=reason,
                    action=action,
                )

                post_to_slack(slack_webhook_url, payload)

        append_rows_to_sheet(sheets, spreadsheet_id, output_rows)

        if not output_rows:
            post_to_slack(
                slack_webhook_url,
                f"✅ CISA KEV定期チェック完了: {now_jst_str}\n"
                f"新規登録対象はありませんでした。システムは正常に動作しています。",
            )

        result = {
            "status": "ok",
            "fetched": len(kev_records),
            "appended": len(output_rows),
            "matched_assets": matched_count,
            "high_notifications": high_notifications,
            "skipped_existing": skipped_count,
        }

        return (
            json.dumps(result, ensure_ascii=False),
            200,
            {"Content-Type": "application/json; charset=utf-8"},
        )

    except Exception as e:
        logging.exception("Unhandled error")

        result = {
            "status": "error",
            "message": str(e),
        }

        return (
            json.dumps(result, ensure_ascii=False),
            500,
            {"Content-Type": "application/json; charset=utf-8"},
        )