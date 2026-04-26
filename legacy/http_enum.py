import requests
from config import HTTP_TIMEOUT, HTTP_HEADERS

def check_http(target, port):
    url = f"http://{target}:{port}"

    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers=HTTP_HEADERS)

        return {
            "url": url,
            "status": r.status_code,
            "headers": dict(r.headers),
            "title": extract_title(r.text)
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


def extract_title(html):
    start = html.lower().find("<title>")
    end = html.lower().find("</title>")

    if start != -1 and end != -1:
        return html[start+7:end].strip()

    return None
