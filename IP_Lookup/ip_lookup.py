import csv
import time

import requests

# Replace with your actual RapidAPI credentials and endpoint:
API_HOST = "ip-lookup-by-api-ninjas.p.rapidapi.com"
API_URL = "https://ip-lookup-by-api-ninjas.p.rapidapi.com/v1/iplookup"
HEADERS = {
    "X-RapidAPI-Key": "Insert_your_api",  # insert your RapidAPI key here
    "X-RapidAPI-Host": API_HOST
}

INPUT_FILE = "IPv4.txt"   # file with one IP address per line
OUTPUT_FILE = "ip_lookup_results.csv"

def lookup_ip(ip):
    try:
        response = requests.get(API_URL, headers=HEADERS, params={"address": ip}, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error for IP {ip}: {response.status_code} {response.text}")
            return None
    except Exception as e:
        print(f"Exception for IP {ip}: {e}")
        return None

def main():
    with open(INPUT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    results = []
    for ip in ips:
        print(f"Looking up: {ip}")
        data = lookup_ip(ip)
        if data:
            result_row = {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
            }
            results.append(result_row)
        else:
            results.append({"ip": ip, "city": None, "region": None, "country": None, "latitude": None, "longitude": None, "isp": None, "asn": None})
        time.sleep(1)  # Be nice to the API, avoid rate limit!

    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        fieldnames = ["ip", "city", "region", "country", "latitude", "longitude", "isp", "asn"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Results saved in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
