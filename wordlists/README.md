# Wordlists

Security testing dictionary files, sourced from [SecLists](https://github.com/danielmiessler/SecLists).

## File List

| File | Source | Purpose |
|------|------|------|
| directories.txt | SecLists/Discovery/Web-Content/common.txt | Directory scanning |
| passwords.txt | SecLists/Passwords/Common-Credentials/10k-most-common.txt | Password brute-forcing |
| usernames.txt | SecLists/Usernames/top-usernames-shortlist.txt | Username enumeration |
| subdomains.txt | SecLists/Discovery/DNS/subdomains-top1million-5000.txt | Subdomain discovery |

## Updating the Wordlists

```bash
# Update the directory wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o directories.txt

# Download the large directory wordlist (optional)
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" -o directories-large.txt

# Update the password wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" -o passwords.txt

# Update the username wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" -o usernames.txt

# Update the subdomain wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o subdomains.txt
```

## License

SecLists uses the MIT license.
