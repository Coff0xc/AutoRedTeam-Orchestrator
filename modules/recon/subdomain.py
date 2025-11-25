"""
Subdomain Scanner - 子域名发现模块
支持多种子域名枚举方式
"""

import asyncio
import logging
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    domain: str
    subdomains: List[str]
    source: str
    count: int


class SubdomainScanner:
    """
    子域名扫描器
    整合多种子域名发现工具
    """
    
    def __init__(self, workspace: str = "/tmp/recon"):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.results: List[SubdomainResult] = []
    
    async def run_subfinder(self, domain: str, threads: int = 50, timeout: int = 180) -> SubdomainResult:
        """使用Subfinder进行被动子域名枚举"""
        output_file = self.workspace / f"subfinder_{domain.replace('.', '_')}.txt"
        
        cmd = ["subfinder", "-d", domain, "-o", str(output_file), "-silent", "-t", str(threads)]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            subdomains = []
            if output_file.exists():
                subdomains = [s.strip() for s in output_file.read_text().split('\n') if s.strip()]
            
            result = SubdomainResult(domain, subdomains, "subfinder", len(subdomains))
            self.results.append(result)
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Subfinder timeout for {domain}")
            return SubdomainResult(domain, [], "subfinder", 0)
        except Exception as e:
            logger.error(f"Subfinder error: {e}")
            return SubdomainResult(domain, [], "subfinder", 0)

    async def run_bruteforce(self, domain: str, wordlist: str = None, threads: int = 100) -> SubdomainResult:
        """使用字典爆破子域名"""
        default_wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        wordlist = wordlist or default_wordlist
        
        if not Path(wordlist).exists():
            logger.warning(f"Wordlist not found: {wordlist}")
            return SubdomainResult(domain, [], "bruteforce", 0)
        
        output_file = self.workspace / f"brute_{domain.replace('.', '_')}.txt"
        
        # 使用dnsx进行爆破
        cmd = ["dnsx", "-d", domain, "-w", wordlist, "-o", str(output_file), "-silent", "-t", str(threads)]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            
            subdomains = []
            if output_file.exists():
                subdomains = [s.strip() for s in output_file.read_text().split('\n') if s.strip()]
            
            result = SubdomainResult(domain, subdomains, "bruteforce", len(subdomains))
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Bruteforce error: {e}")
            return SubdomainResult(domain, [], "bruteforce", 0)

    async def run_permutation(self, domain: str, subdomains: List[str]) -> SubdomainResult:
        """基于已发现子域名生成排列组合"""
        permutations = set()
        prefixes = ['dev', 'test', 'staging', 'uat', 'api', 'admin', 'internal', 'new', 'old', 'backup']
        
        for sub in subdomains[:20]:  # 限制数量
            parts = sub.replace(f".{domain}", "").split('.')
            for prefix in prefixes:
                permutations.add(f"{prefix}-{parts[0]}.{domain}")
                permutations.add(f"{parts[0]}-{prefix}.{domain}")
                permutations.add(f"{prefix}.{parts[0]}.{domain}")
        
        # 验证这些排列是否存在
        valid = await self._validate_subdomains(list(permutations))
        
        result = SubdomainResult(domain, valid, "permutation", len(valid))
        self.results.append(result)
        return result

    async def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """验证子域名是否存在"""
        if not subdomains:
            return []
        
        input_file = self.workspace / "validate_input.txt"
        output_file = self.workspace / "validate_output.txt"
        
        input_file.write_text('\n'.join(subdomains))
        
        cmd = ["dnsx", "-l", str(input_file), "-o", str(output_file), "-silent"]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            
            if output_file.exists():
                return [s.strip() for s in output_file.read_text().split('\n') if s.strip()]
            return []
        except:
            return []

    def merge_results(self) -> List[str]:
        """合并所有结果并去重"""
        all_subs = set()
        for result in self.results:
            all_subs.update(result.subdomains)
        return sorted(list(all_subs))

    async def full_scan(self, domain: str) -> List[str]:
        """执行完整的子域名扫描流程"""
        logger.info(f"[*] Starting full subdomain scan for: {domain}")
        
        # 1. Subfinder被动枚举
        subfinder_result = await self.run_subfinder(domain)
        logger.info(f"    [+] Subfinder: {subfinder_result.count} subdomains")
        
        # 2. 如果结果较少，尝试爆破
        if subfinder_result.count < 10:
            brute_result = await self.run_bruteforce(domain)
            logger.info(f"    [+] Bruteforce: {brute_result.count} subdomains")
        
        # 3. 排列组合
        if subfinder_result.subdomains:
            perm_result = await self.run_permutation(domain, subfinder_result.subdomains)
            logger.info(f"    [+] Permutation: {perm_result.count} subdomains")
        
        merged = self.merge_results()
        logger.info(f"    [*] Total unique subdomains: {len(merged)}")
        
        return merged
