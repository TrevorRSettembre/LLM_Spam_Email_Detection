import email
from email import policy
import re


URL_REGEX = re.compile(r"https?://[^\s<>\"'\]]+", re.I)
HREF_REGEX = re.compile(r'href\s*=\s*["\']?(https?://[^"\'>\s]+)', re.I)
SRC_REGEX = re.compile(r'src\s*=\s*["\']?(https?://[^"\'>\s]+)', re.I)
FORM_REGEX = re.compile(r'action\s*=\s*["\']?(https?://[^"\'>\s]+)', re.I)


def parse_eml(path):
    with open(path, "rb") as f:
        raw = f.read()

    if raw.startswith(b"From "):
        raw = raw.split(b"\n", 1)[1]

    return email.message_from_bytes(raw, policy=policy.default)


def extract_headers(msg):
    headers = {
        "From": msg.get("From", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Subject": msg.get("Subject", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "User-Agent": msg.get("User-Agent", ""),
        "X-Mailer": msg.get("X-Mailer", ""),
        "X-PHP-Script": msg.get("X-PHP-Script", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
    }

    received_chain = msg.get_all("Received", []) or []
    headers["Received_Count"] = len(received_chain)
    headers["Received"] = received_chain

    return headers


def extract_body(msg):
 
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition.lower():
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if not isinstance(content, str):
                continue

            if content_type == "text/plain":
                plain_parts.append(content)
            elif content_type == "text/html":
                html_parts.append(content)
    else:
        try:
            content = msg.get_content()
            if isinstance(content, str):
                if msg.get_content_type() == "text/plain":
                    plain_parts.append(content)
                elif msg.get_content_type() == "text/html":
                    html_parts.append(content)
        except Exception:
            pass

    if plain_parts:
        return "\n".join(plain_parts).strip()

    if html_parts:
        return "\n".join(html_parts).strip()

    return ""


def normalize_text_for_url_extraction(text):
  
    if not text:
        return ""

    text = text.replace("=\r\n", "")
    text = text.replace("=\n", "")
    text = text.replace("&amp;", "&")

    return text


def extract_urls(text):
    
    if not text:
        return []

    normalized = normalize_text_for_url_extraction(text)

    urls = set()
    urls.update(URL_REGEX.findall(normalized))
    urls.update(HREF_REGEX.findall(normalized))
    urls.update(SRC_REGEX.findall(normalized))
    urls.update(FORM_REGEX.findall(normalized))

    return sorted(urls)