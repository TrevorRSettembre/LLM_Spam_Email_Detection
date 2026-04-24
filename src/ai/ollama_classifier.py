import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import ollama


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def load_config(config_path: Path) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


CONFIG = load_config(CONFIG_PATH)

MODEL_NAME = CONFIG["model"]["name"]
TEMPERATURE = CONFIG["model"].get("temperature", 0.0)
TOP_P = CONFIG["model"].get("top_p", 0.1)
BODY_LIMIT = CONFIG["email_processing"].get("body_char_limit", 2500)

PROMPT_PATH = BASE_DIR / CONFIG["model"]["prompt_file"]
PROMPT_TEMPLATE = PROMPT_PATH.read_text(encoding="utf-8")

IP_HOST_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$", re.I)
EMAIL_DOMAIN_REGEX = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

KNOWN_BRANDS = [
    "ebay",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "bank",
    "wells fargo",
    "chase",
    "netflix",
    "google",
    "facebook",
    "instagram",
]

SUSPICIOUS_TLDS = (
    ".xyz",
    ".top",
    ".click",
    ".vip",
    ".shop",
    ".ru",
    ".cn",
    ".tk",
    ".gq",
)

URL_SHORTENERS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rb.gy",
    "ow.ly",
    "buff.ly",
)

VALID_LABELS = {"legitimate", "automated", "phishing"}


class Logger:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def log(self, message: str = "") -> None:
        if self.enabled:
            print(message)


def ensure_ollama_running(logger: Logger) -> None:
    try:
        ollama.list()
        logger.log("[DEBUG] Ollama is already running.")
    except Exception:
        logger.log("[DEBUG] Ollama not running. Starting ollama serve...")
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        logger.log("[DEBUG] Waited 2 seconds for Ollama startup.")


def extract_domain(value: str) -> str:
    if not value:
        return ""

    value = str(value).strip()

    match = EMAIL_DOMAIN_REGEX.search(value)
    if match:
        return match.group(1).lower()

    inner_match = re.search(r"<([^>]+)>", value)
    if inner_match:
        value = inner_match.group(1).strip()

    if "@" in value:
        return value.split("@")[-1].strip().lower()

    return value.lower()


def get_root_domain(domain: str) -> str:
    if not domain:
        return ""

    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def detect_brand_mentions(text: str) -> list[str]:
    text_lower = (text or "").lower()
    return [brand for brand in KNOWN_BRANDS if brand in text_lower]


def build_header_indicators(headers: dict) -> dict:
    from_raw = headers.get("From", "")
    reply_to_raw = headers.get("Reply-To", "")
    return_path_raw = headers.get("Return-Path", "")
    subject = headers.get("Subject", "")

    from_domain = extract_domain(from_raw)
    reply_to_domain = extract_domain(reply_to_raw)
    return_path_domain = extract_domain(return_path_raw)

    domains = [d for d in [from_domain, reply_to_domain, return_path_domain] if d]
    domain_mismatch = len(set(domains)) > 1 if domains else False

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "from_root_domain": get_root_domain(from_domain),
        "reply_to_root_domain": get_root_domain(reply_to_domain),
        "return_path_root_domain": get_root_domain(return_path_domain),
        "domain_mismatch": domain_mismatch,
        "x_mailer_or_user_agent": headers.get("X-Mailer", "") or headers.get("User-Agent", ""),
        "auth_results_summary": headers.get("Authentication-Results", ""),
        "received_count": headers.get("Received_Count", 0),
        "subject": subject,
        "from_raw": from_raw,
        "reply_to_raw": reply_to_raw,
        "return_path_raw": return_path_raw,
    }


def build_url_indicators(urls: list[str], header_indicators: dict, body: str) -> dict:
    suspicious_urls: list[str] = []
    ip_url_count = 0
    brand_mismatch = False
    shortened_url_count = 0
    suspicious_tld_count = 0
    suspicious_path_count = 0

    from_domain = header_indicators.get("from_domain", "")
    from_root = get_root_domain(from_domain)
    body_brands = detect_brand_mentions(body or "")

    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()

            if not host:
                continue

            if IP_HOST_REGEX.match(host):
                ip_url_count += 1
                suspicious_urls.append(url)

            if any(shortener in host for shortener in URL_SHORTENERS):
                shortened_url_count += 1
                suspicious_urls.append(url)

            if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                suspicious_tld_count += 1
                suspicious_urls.append(url)

            if any(keyword in path for keyword in ["login", "signin", "verify", "account", "password", "secure", "update"]):
                suspicious_path_count += 1

            host_root = get_root_domain(host)

            if body_brands and host_root:
                for brand in body_brands:
                    brand_token = brand.replace(" ", "")
                    normalized_host = host.replace("-", "").replace(".", "")
                    normalized_host_root = host_root.replace(".", "")
                    if brand_token in normalized_host and brand_token not in normalized_host_root:
                        brand_mismatch = True
                        suspicious_urls.append(url)

            if from_root and host_root and from_root != host_root and body_brands:
                brand_mismatch = True

        except Exception:
            continue

    return {
        "url_count": len(urls),
        "ip_url_count": ip_url_count,
        "shortened_url_count": shortened_url_count,
        "suspicious_tld_count": suspicious_tld_count,
        "suspicious_path_count": suspicious_path_count,
        "suspicious_urls": list(dict.fromkeys(suspicious_urls))[:10],
        "brand_mismatch": brand_mismatch,
    }


def build_prompt(
    headers: dict,
    urls: list[str],
    body: str,
    header_indicators: dict,
    url_indicators: dict,
    rule_summary: dict | None = None,
) -> str:
    body_excerpt = (body or "")[:BODY_LIMIT]

    return PROMPT_TEMPLATE.format(
        headers=json.dumps(headers, indent=2, ensure_ascii=False),
        urls=json.dumps(urls, indent=2, ensure_ascii=False),
        header_indicators=json.dumps(header_indicators, indent=2, ensure_ascii=False),
        url_indicators=json.dumps(url_indicators, indent=2, ensure_ascii=False),
        body=body_excerpt,
        rule_summary=json.dumps(rule_summary or {}, indent=2, ensure_ascii=False),
    )


def extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]

    return None


def empty_result(
    decision: str,
    evidence_text: str = "",
    header_indicators: dict | None = None,
    url_indicators: dict | None = None,
) -> dict:
    return {
        "label": "unknown",
        "confidence": 0.0,
        "decision": decision,
        "evidence": [evidence_text] if evidence_text else [],
        "header_indicators": header_indicators or {
            "from_domain": "",
            "reply_to_domain": "",
            "return_path_domain": "",
            "domain_mismatch": False,
            "x_mailer_or_user_agent": "",
            "auth_results_summary": "",
            "received_count": 0,
        },
        "url_indicators": url_indicators or {
            "url_count": 0,
            "ip_url_count": 0,
            "shortened_url_count": 0,
            "suspicious_tld_count": 0,
            "suspicious_path_count": 0,
            "suspicious_urls": [],
            "brand_mismatch": False,
        },
    }


def clean_result_schema(result: dict, header_indicators: dict, url_indicators: dict) -> dict:
    cleaned = {
        "label": result.get("label", "unknown"),
        "confidence": result.get("confidence", 0.0),
        "decision": result.get("decision", "No decision returned."),
        "evidence": result.get("evidence", []),
        "header_indicators": header_indicators,
        "url_indicators": url_indicators,
    }

    if cleaned["label"] not in VALID_LABELS:
        cleaned["label"] = "unknown"

    try:
        cleaned["confidence"] = float(cleaned["confidence"])
    except (TypeError, ValueError):
        cleaned["confidence"] = 0.0

    cleaned["confidence"] = max(0.0, min(1.0, cleaned["confidence"]))

    if not isinstance(cleaned["decision"], str):
        cleaned["decision"] = str(cleaned["decision"])

    if not isinstance(cleaned["evidence"], list):
        cleaned["evidence"] = []

    cleaned["evidence"] = [str(item) for item in cleaned["evidence"][:8]]
    return cleaned


def parse_json_response(raw_text: str, header_indicators: dict, url_indicators: dict) -> dict:
    raw_text = raw_text.strip()

    try:
        parsed = json.loads(raw_text)
        return clean_result_schema(parsed, header_indicators, url_indicators)
    except json.JSONDecodeError:
        pass

    json_block = extract_first_json_object(raw_text)
    if json_block:
        try:
            parsed = json.loads(json_block)
            return clean_result_schema(parsed, header_indicators, url_indicators)
        except json.JSONDecodeError:
            pass

    return empty_result(
        "Model returned invalid JSON.",
        raw_text[:300],
        header_indicators,
        url_indicators,
    )


def score_email_rules(
    headers: dict,
    urls: list[str],
    body: str,
    header_indicators: dict,
    url_indicators: dict,
) -> dict:
    body_lower = (body or "").lower()
    subject_lower = (headers.get("Subject", "") or "").lower()

    phishing_score = 0
    automated_score = 0
    legitimate_score = 0

    phishing_evidence: list[str] = []
    automated_evidence: list[str] = []
    legitimate_evidence: list[str] = []

    from_domain = header_indicators.get("from_domain", "")
    from_root = header_indicators.get("from_root_domain", "")
    reply_to_root = header_indicators.get("reply_to_root_domain", "")
    return_path_root = header_indicators.get("return_path_root_domain", "")

    auth_summary = (header_indicators.get("auth_results_summary", "") or "").lower()
    x_mailer = (header_indicators.get("x_mailer_or_user_agent", "") or "").lower()

    if header_indicators.get("domain_mismatch"):
        phishing_score += 2
        phishing_evidence.append("Header domain mismatch detected")

    if from_root and reply_to_root and from_root != reply_to_root:
        phishing_score += 2
        phishing_evidence.append("Reply-To root domain mismatch")

    if from_root and return_path_root and from_root != return_path_root:
        phishing_score += 2
        phishing_evidence.append("Return-Path root domain mismatch")

    if header_indicators.get("received_count", 0) >= 4:
        automated_score += 1
        automated_evidence.append("Multiple Received headers")

    if auth_summary:
        if "spf=fail" in auth_summary or "dkim=fail" in auth_summary or "dmarc=fail" in auth_summary:
            phishing_score += 2
            phishing_evidence.append("Authentication failure in headers")
    elif phishing_score > 0:
        phishing_score += 1
        phishing_evidence.append("No authentication summary with other suspicious indicators")

    if "no-reply" in from_domain or "noreply" in from_domain:
        automated_score += 2
        automated_evidence.append("No-reply sender detected")

    if x_mailer and any(k in x_mailer for k in ["mailchimp", "sendgrid", "constant contact", "mailer"]):
        automated_score += 2
        automated_evidence.append("Bulk mailer identified in headers")

    if url_indicators.get("ip_url_count", 0) > 0:
        phishing_score += 3
        phishing_evidence.append("Raw IP URL detected")

    if url_indicators.get("brand_mismatch", False):
        phishing_score += 2
        phishing_evidence.append("Brand mismatch detected")

    if url_indicators.get("shortened_url_count", 0) > 0:
        phishing_score += 2
        phishing_evidence.append("Shortened URL detected")

    if url_indicators.get("suspicious_tld_count", 0) > 0:
        phishing_score += 2
        phishing_evidence.append("Suspicious TLD detected in URL")

    if url_indicators.get("suspicious_path_count", 0) > 0:
        phishing_score += 1
        phishing_evidence.append("Suspicious login or account path in URL")

    if url_indicators.get("url_count", 0) >= 8:
        automated_score += 2
        automated_evidence.append("High URL count")

    phishing_phrases = [
        "verify your account",
        "confirm your account",
        "update your account",
        "re-confirm your account",
        "urgent action required",
        "security alert",
        "account suspended",
        "account limited",
        "account has been limited",
        "account indefinitely",
        "billing issue",
        "billing issues",
        "password failures",
        "fraudulent purposes",
        "logged onto your account",
        "click below",
        "login immediately",
        "reset your password",
        "unauthorized login",
        "suspend your account",
    ]
    if any(p in body_lower for p in phishing_phrases):
        phishing_score += 2
        phishing_evidence.append("Phishing-style account or threat language")

    generic_greetings = ["dear customer", "dear user", "valued customer", "dear client"]
    if any(g in body_lower for g in generic_greetings):
        phishing_score += 1
        phishing_evidence.append("Generic greeting detected")

    if any(k in body_lower for k in ["social security", "ssn", "bank account", "credit card", "password", "login credentials"]):
        phishing_score += 2
        phishing_evidence.append("Sensitive information request language detected")

    automated_phrases = [
        "unsubscribe",
        "manage preferences",
        "view in browser",
        "newsletter",
        "special offer",
        "limited time offer",
        "receipt",
        "order confirmation",
        "tracking number",
        "notification",
        "do not reply",
        "system alert",
        "privacy policy",
        "terms of service",
    ]
    if any(p in body_lower for p in automated_phrases):
        automated_score += 2
        automated_evidence.append("Automated or marketing language detected")

    if any(p in subject_lower for p in ["receipt", "invoice", "order", "shipment", "tracking", "newsletter", "alert"]):
        automated_score += 1
        automated_evidence.append("Automated-style subject detected")

    legitimate_phrases = [
        "let me know",
        "thank you",
        "thanks",
        "attached",
        "meeting",
        "call me",
        "see you",
        "following up",
        "per our conversation",
        "talk soon",
    ]
    if any(p in body_lower for p in legitimate_phrases):
        legitimate_score += 1
        legitimate_evidence.append("Conversational language detected")

    if url_indicators.get("url_count", 0) == 0:
        legitimate_score += 1
        legitimate_evidence.append("No URLs detected")

    if not header_indicators.get("domain_mismatch") and from_root and from_root == reply_to_root == return_path_root:
        legitimate_score += 1
        legitimate_evidence.append("Header domains are aligned")

    if phishing_score >= 5 and phishing_score > automated_score:
        return {
            "label": "phishing",
            "confidence": min(0.99, 0.55 + 0.05 * phishing_score),
            "decision": "Rules indicate phishing behavior based on header, URL, and body indicators.",
            "evidence": phishing_evidence[:8],
            "phishing_score": phishing_score,
            "automated_score": automated_score,
            "legitimate_score": legitimate_score,
            "header_indicators": header_indicators,
            "url_indicators": url_indicators,
        }

    if automated_score >= 4 and automated_score >= phishing_score:
        return {
            "label": "automated",
            "confidence": min(0.95, 0.55 + 0.05 * automated_score),
            "decision": "Rules indicate automated or bulk email behavior.",
            "evidence": automated_evidence[:8],
            "phishing_score": phishing_score,
            "automated_score": automated_score,
            "legitimate_score": legitimate_score,
            "header_indicators": header_indicators,
            "url_indicators": url_indicators,
        }

    return {
        "label": "legitimate",
        "confidence": 0.60 if legitimate_score > 0 else 0.50,
        "decision": "Rules did not find strong phishing or automated indicators.",
        "evidence": legitimate_evidence[:8],
        "phishing_score": phishing_score,
        "automated_score": automated_score,
        "legitimate_score": legitimate_score,
        "header_indicators": header_indicators,
        "url_indicators": url_indicators,
    }


def merge_model_and_rules(model_result: dict, rule_result: dict) -> dict:
    if model_result.get("label") == "unknown":
        return {
            "label": rule_result["label"],
            "confidence": rule_result["confidence"],
            "decision": rule_result["decision"],
            "evidence": rule_result["evidence"],
            "header_indicators": rule_result["header_indicators"],
            "url_indicators": rule_result["url_indicators"],
        }

    model_label = model_result.get("label")
    rule_label = rule_result.get("label")

    if model_label == rule_label:
        merged = dict(model_result)
        merged["confidence"] = max(
            float(model_result.get("confidence", 0.0)),
            float(rule_result.get("confidence", 0.0)),
        )

        combined_evidence = model_result.get("evidence", []) + rule_result.get("evidence", [])
        deduped: list[str] = []
        for item in combined_evidence:
            if item not in deduped:
                deduped.append(item)

        merged["evidence"] = deduped[:8]
        return merged

    if rule_label == "phishing" and float(rule_result.get("confidence", 0.0)) >= 0.75:
        return {
            "label": rule_result["label"],
            "confidence": rule_result["confidence"],
            "decision": rule_result["decision"],
            "evidence": rule_result["evidence"],
            "header_indicators": rule_result["header_indicators"],
            "url_indicators": rule_result["url_indicators"],
        }

    if model_label == "phishing" and float(model_result.get("confidence", 0.0)) >= 0.75:
        return model_result

    return model_result


def run_llm_thinking(prompt: str, logger: Logger) -> str:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a digital forensics analyst.\n\n"
                "Analyze the email step-by-step using the provided headers, URLs, indicators, body excerpt, "
                "and rule summary.\n\n"
                "Discuss:\n"
                "- Header analysis\n"
                "- URL analysis\n"
                "- Body and social engineering analysis\n"
                "- Final conclusion\n\n"
                "Do not output JSON. Write a clear plain-text analysis."
            ),
        },
        {
            "role": "user",
            "content": prompt,
        },
    ]

    start_time = time.time()
    response = ollama.chat(
        model=MODEL_NAME,
        messages=messages,
        options={
            "temperature": TEMPERATURE,
            "top_p": TOP_P,
        },
    )
    elapsed = time.time() - start_time
    logger.log(f"[DEBUG] LLM thinking response time: {elapsed:.2f}s")
    return response["message"]["content"].strip()


def run_llm_json(prompt: str, logger: Logger) -> str:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a digital forensics email classifier. "
                "Return exactly one valid JSON object and nothing else. "
                "Do not use markdown. Do not explain outside the JSON."
            ),
        },
        {
            "role": "user",
            "content": prompt,
        },
    ]

    start_time = time.time()
    response = ollama.chat(
        model=MODEL_NAME,
        messages=messages,
        options={
            "temperature": TEMPERATURE,
            "top_p": TOP_P,
        },
    )
    elapsed = time.time() - start_time
    logger.log(f"[DEBUG] LLM constrained response time: {elapsed:.2f}s")
    return response["message"]["content"].strip()


def classify_email(
    headers: dict,
    urls: list[str],
    body: str,
    start_ollama: bool = False,
    debug: bool = False,
    return_thinking: bool = False,
) -> dict:
    logger = Logger(enabled=debug)

    if start_ollama:
        ensure_ollama_running(logger)

    header_indicators = build_header_indicators(headers)
    url_indicators = build_url_indicators(urls, header_indicators, body)

    try:
        rule_result = score_email_rules(headers, urls, body, header_indicators, url_indicators)

        rule_summary = {
            "phishing_score": rule_result.get("phishing_score", 0),
            "automated_score": rule_result.get("automated_score", 0),
            "legitimate_score": rule_result.get("legitimate_score", 0),
            "rule_label": rule_result.get("label", "unknown"),
            "rule_evidence": rule_result.get("evidence", []),
        }

        prompt = build_prompt(
            headers=headers,
            urls=urls,
            body=body,
            header_indicators=header_indicators,
            url_indicators=url_indicators,
            rule_summary=rule_summary,
        )

        thinking = None
        if return_thinking:
            thinking = run_llm_thinking(prompt, logger)

        raw_result = run_llm_json(prompt, logger)
        model_result = parse_json_response(raw_result, header_indicators, url_indicators)
        final_result = merge_model_and_rules(model_result, rule_result)

        if debug:
            logger.log("=== RULE SUMMARY ===")
            logger.log(json.dumps(rule_summary, indent=2))
            logger.log("====================")

            if thinking:
                logger.log("=== MODEL THINKING ===")
                logger.log(thinking)
                logger.log("======================")

            logger.log("=== MODEL JSON RESULT ===")
            logger.log(json.dumps(model_result, indent=2))
            logger.log("=========================")

            logger.log("=== FINAL RESULT ===")
            logger.log(json.dumps(final_result, indent=2))
            logger.log("====================")

        return {
            "thinking": thinking,
            "result": final_result,
            "raw_model_output": raw_result,
            "rule_summary": rule_summary,
        }

    except Exception as e:
        return {
            "thinking": None,
            "result": empty_result(
                f"Classifier error: {str(e)}",
                header_indicators=header_indicators,
                url_indicators=url_indicators,
            ),
            "raw_model_output": "",
            "rule_summary": {},
        }