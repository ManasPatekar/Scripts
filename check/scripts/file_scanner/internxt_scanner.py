import urllib.request
import urllib.error
import json
import sys
import argparse
import os
import mimetypes

def scan_file(file_path):
    print(f"[*] Uploading {file_path} to Internxt ClamAV scanner...")
    url = "https://clamav.internxt.com/filescan"
    
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        sys.exit(1)

    filename = os.path.basename(file_path)
    mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
    
    boundary = '----WebKitFormBoundary1NYlc7JnUU3SGixp'
    body = []
    
    body.append(f"--{boundary}")
    # Note: Internxt might expect a specific field name, we'll try "file" or just follow standard multipart.
    # Looking at the user's headers, they didn't specify the field name in the trace, but commonly it's "file" or "files"
    # Wait, the user didn't show the payload field name, but "file" is most common.
    body.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"')
    body.append(f'Content-Type: {mime_type}')
    body.append('')
    
    with open(file_path, 'rb') as f:
        file_content = f.read()
        
    body_str = '\r\n'.join(body) + '\r\n'
    body_bytes = body_str.encode('utf-8') + file_content + f'\r\n--{boundary}--\r\n'.encode('utf-8')
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "*/*",
        "Origin": "https://internxt.com",
        "Referer": "https://internxt.com/"
    }
    
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("\n[+] Scan Complete!")
            print("="*50)
            
            is_infected = result.get('isInfected', False)
            viruses = result.get('viruses', [])
            
            if is_infected:
                print(f"[!] DANGER: File is INFECTED!")
                for virus in viruses:
                    print(f"    - {virus}")
            else:
                print(f"[*] Result: CLEAN (No infections found)")
            print("="*50)
            
    except urllib.error.URLError as e:
        if hasattr(e, 'read'):
            print(f"[-] Error from server: {e.read().decode(errors='ignore')}")
        print(f"[-] Error uploading: {e}")
    except json.JSONDecodeError:
        print("[-] Error parsing JSON response from Internxt.")

def main():
    parser = argparse.ArgumentParser(description="Upload files to Internxt ClamAV scanner.")
    parser.add_argument("file_path", help="Path to the file to scan")
    
    args = parser.parse_args()
    scan_file(args.file_path)

if __name__ == "__main__":
    main()
