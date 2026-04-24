from pathlib import Path
import json

from utils.email_parser import parse_eml, extract_headers, extract_body, extract_urls
from ai.ollama_classifier import classify_email


def print_human_output(file_path: Path, thinking: str | None, result: dict) -> None:
    print(f"\nFile: {file_path}")

    if thinking:
        print("\n=== MODEL THINKING ===")
        print(thinking)
        print("======================")

    print("\n=== CONSTRAINED OUTPUT ===")
    print(f"Label      : {result['label']}")
    print(f"Confidence : {result['confidence']:.2f}")
    print(f"Decision   : {result['decision']}")

    if result.get("evidence"):
        print("Evidence:")
        for e in result["evidence"]:
            print(f"  - {e}")

    header_indicators = result.get("header_indicators", {})
    url_indicators = result.get("url_indicators", {})

    print("Headers:")
    print(f"  From domain      : {header_indicators.get('from_domain', '')}")
    print(f"  Reply-To domain  : {header_indicators.get('reply_to_domain', '')}")
    print(f"  Return-Path      : {header_indicators.get('return_path_domain', '')}")
    print(f"  Domain mismatch  : {header_indicators.get('domain_mismatch', False)}")
    print(f"  Received count   : {header_indicators.get('received_count', 0)}")
    print(f"  Subject          : {header_indicators.get('subject', '')}")

    print("URLs:")
    print(f"  URL count         : {url_indicators.get('url_count', 0)}")
    print(f"  IP URL count      : {url_indicators.get('ip_url_count', 0)}")
    print(f"  Shortened URLs    : {url_indicators.get('shortened_url_count', 0)}")
    print(f"  Suspicious TLDs   : {url_indicators.get('suspicious_tld_count', 0)}")
    print(f"  Suspicious paths  : {url_indicators.get('suspicious_path_count', 0)}")
    print(f"  Brand mismatch    : {url_indicators.get('brand_mismatch', False)}")

    suspicious_urls = url_indicators.get("suspicious_urls", [])
    if suspicious_urls:
        print("  Suspicious URLs:")
        for url in suspicious_urls:
            print(f"    - {url}")

    print("----")


def process_email(
    file_path: Path,
    debug: bool = False,
    as_json: bool = False,
    show_thinking: bool = True,
) -> None:
    msg = parse_eml(file_path)
    headers = extract_headers(msg)
    body = extract_body(msg)
    urls = extract_urls(body)

    output = classify_email(
        headers=headers,
        urls=urls,
        body=body,
        start_ollama=False,
        debug=debug,
        return_thinking=show_thinking,
    )

    thinking = output.get("thinking")
    result = output["result"]

    if as_json:
        payload = {
            "file": str(file_path),
            "thinking": thinking,
            "result": result,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_human_output(file_path, thinking, result)


if __name__ == "__main__":
    base_dir = Path("../data/public_phishing/phishing0")
    i = 0

    while True:
        file_path = base_dir / f"{i}.eml"

        if not file_path.exists():
            print(f"\nNo file found: {file_path}")
            break

        process_email(file_path, debug=False, as_json=False, show_thinking=True)

        user_input = input("\nPress ENTER for next email or type q to quit: ").strip().lower()
        if user_input == "q":
            break

        i += 1