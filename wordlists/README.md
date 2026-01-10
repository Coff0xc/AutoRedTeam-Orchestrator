# Wordlists

安全测试字典文件，来源于 [SecLists](https://github.com/danielmiessler/SecLists)。

## 文件列表

| 文件 | 来源 | 用途 |
|------|------|------|
| directories.txt | SecLists/Discovery/Web-Content/common.txt | 目录扫描 |
| passwords.txt | SecLists/Passwords/Common-Credentials/10k-most-common.txt | 密码爆破 |
| usernames.txt | SecLists/Usernames/top-usernames-shortlist.txt | 用户名枚举 |
| subdomains.txt | SecLists/Discovery/DNS/subdomains-top1million-5000.txt | 子域名发现 |

## 更新字典

```bash
# 更新目录字典
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o directories.txt

# 下载大型目录字典 (可选)
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" -o directories-large.txt

# 更新密码字典
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" -o passwords.txt

# 更新用户名字典
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" -o usernames.txt

# 更新子域名字典
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o subdomains.txt
```

## 许可证

SecLists 使用 MIT 许可证。
