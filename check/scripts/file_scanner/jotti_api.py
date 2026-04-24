import urllib.request
import urllib.error
import json
import sys
import argparse
import time
import os
import mimetypes
import hashlib

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def check_jotti_scan(job_id, poll_interval=0):
    url = f"https://virusscan.jotti.org/ajax/filescanjobprogress.php?id={job_id}&lang=en-US"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    
    print(f"[*] Fetching scan results for job ID: {job_id}")
    
    while True:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                
                meta = data.get("meta", {})
                status = meta.get("statustext", "Unknown status")
                finish_stamp = meta.get("finishstamp")
                
                print(f"[*] Status: {status}")
                
                if poll_interval > 0 and not finish_stamp:
                    print(f"[*] Scan in progress. Waiting {poll_interval} seconds...")
                    time.sleep(poll_interval)
                    continue

                scanners = data.get("filescanner", {})
                
                if not scanners:
                    print("[!] No scanner results available yet.")
                    if poll_interval > 0:
                        time.sleep(poll_interval)
                        continue
                    return

                print("\n" + "="*50)
                print(f"{'Scanner':<20} | {'Result':<20} | {'Malware Name'}")
                print("="*50)
                
                malware_found = 0
                total_scanners = len(scanners)
                
                for scanner, info in scanners.items():
                    result = info.get("resulttext", "Unknown")
                    malware_name = info.get("malwarename", "")
                    
                    if result != "Found nothing" and result != "Unknown":
                        malware_found += 1
                    
                    print(f"{scanner.capitalize():<20} | {result:<20} | {malware_name}")
                
                print("="*50)
                print(f"[*] Summary: {malware_found}/{total_scanners} scanners reported malware.")
                break

        except urllib.error.URLError as e:
            print(f"[-] Error connecting to Jotti: {e}")
            break
        except json.JSONDecodeError:
            print("[-] Error parsing JSON response.")
            break

def check_hash(file_path):
    md5_hash = calculate_md5(file_path)
    print(f"[*] Calculated MD5: {md5_hash}")
    url = f"https://virusscan.jotti.org/en-US/search/hash/{md5_hash}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)
        http_error_301 = http_error_303 = http_error_307 = http_error_302
        
    opener = urllib.request.build_opener(NoRedirectHandler())
    
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req) as response:
            pass # 200 OK means it didn't redirect, maybe hash not found or it just returned HTML directly. 
            # If it returns HTML directly, we need to extract the job ID from the HTML or it means no redirect.
            html = response.read().decode(errors='ignore')
            if 'filescanjob/' in html:
                # sometimes Jotti returns a 200 OK with the job page directly if hash is found.
                # let's try to find the job ID in the HTML.
                import re
                match = re.search(r'filescanjob/([a-z0-9]+)', html)
                if match:
                    return match.group(1)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            location = e.headers.get('Location')
            if location and '/filescanjob/' in location:
                return location.split('/')[-1]
    except Exception as e:
        pass
    
    return None

def upload_file(file_path):
    # First check if the file has already been scanned
    print("[*] Checking if file has already been scanned...")
    existing_job_id = check_hash(file_path)
    if existing_job_id:
        print(f"[+] File already scanned! Instant results available. Job ID: {existing_job_id}")
        return existing_job_id, True

    print(f"[*] Hash not found. Uploading {file_path} to Jotti...")
    url = "https://virusscan.jotti.org/en-US/submit-file"
    
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        sys.exit(1)

    filename = os.path.basename(file_path)
    mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
    
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    body = []
    body.append(f"--{boundary}")
    body.append(f'Content-Disposition: form-data; name="sample-file[]"; filename="{filename}"')
    body.append(f'Content-Type: {mime_type}')
    body.append('')
    
    with open(file_path, 'rb') as f:
        file_content = f.read()
        
    body_str = '\r\n'.join(body) + '\r\n'
    body_bytes = body_str.encode('utf-8') + file_content + f'\r\n--{boundary}--\r\n'.encode('utf-8')
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json"
    }
    
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)
        http_error_301 = http_error_303 = http_error_307 = http_error_302
        
    opener = urllib.request.build_opener(NoRedirectHandler())

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    try:
        with opener.open(req) as response:
            print(f"[-] Unexpected success. HTTP Status: {response.status}")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            location = e.headers.get('Location')
            if location and '/filescanjob/' in location:
                job_id = location.split('/')[-1]
                print(f"[+] Upload successful! Job ID: {job_id}")
                return job_id, False
        print(f"[-] Upload failed. HTTP Status: {e.code}")
    except urllib.error.URLError as e:
        print(f"[-] Error uploading: {e}")
        
    return None, False

def main():
    parser = argparse.ArgumentParser(description="Upload files and fetch Jotti malware scan results.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    upload_parser = subparsers.add_parser("upload", help="Upload a file (or fetch instant results if previously scanned) and poll for results")
    upload_parser.add_argument("file_path", help="Path to the file to upload")
    
    poll_parser = subparsers.add_parser("poll", help="Poll for existing scan results")
    poll_parser.add_argument("job_id", help="The Job ID from the Jotti scan URL")
    
    args = parser.parse_args()
    
    if args.command == "upload":
        job_id, instantly_found = upload_file(args.file_path)
        if job_id:
            if instantly_found:
                check_jotti_scan(job_id)
            else:
                print("[*] Starting polling for results...")
                check_jotti_scan(job_id, poll_interval=5)
    elif args.command == "poll":
        check_jotti_scan(args.job_id)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
