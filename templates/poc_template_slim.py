#!/usr/bin/env python3
"""精简版PoC模板"""
import argparse, logging, sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
import requests

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

@dataclass
class Config:
    target: str
    timeout: int = 10
    proxy: str = ""
    verify_ssl: bool = True
    cmd: str = "id"
    def __post_init__(self):
        if not self.target.startswith(("http://", "https://")) or not urlparse(self.target).netloc:
            raise ValueError("Invalid target URL")
    @property
    def proxies(self) -> dict | None:
        return {"http": self.proxy, "https": self.proxy} if self.proxy else None

@dataclass
class Result:
    success: bool
    msg: str
    data: dict[str, Any] = field(default_factory=dict)

class BasePoC(ABC):
    name, cve = "Base", "N/A"
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.verify, self.s.proxies = cfg.verify_ssl, cfg.proxies

    @abstractmethod
    def check(self) -> Result: ...
    @abstractmethod
    def exploit(self) -> Result: ...

    def run(self, check_only: bool = False) -> Result:
        log.info(f"Target: {self.cfg.target}")
        r = self.check()
        log.info(f"Check: {'Vuln' if r.success else 'Safe'}")
        if r.success and not check_only:
            r = self.exploit()
            log.info(f"Exploit: {'OK' if r.success else 'Fail'}")
        return r

class ExamplePoC(BasePoC):
    name, cve = "Example RCE", "CVE-2024-XXXX"
    def check(self) -> Result:
        try:
            r = self.s.get(f"{self.cfg.target}/vuln", timeout=self.cfg.timeout)
            return Result("marker" in r.text, "Detected" if "marker" in r.text else "Safe")
        except Exception as e:
            return Result(False, str(e))
    def exploit(self) -> Result:
        try:
            r = self.s.post(f"{self.cfg.target}/rce", json={"cmd": self.cfg.cmd}, timeout=self.cfg.timeout)
            return Result(r.ok, "Done", {"out": r.text[:500]})
        except Exception as e:
            return Result(False, str(e))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-c", "--cmd", default="id")
    p.add_argument("--proxy", default="")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--check-only", action="store_true")
    a = p.parse_args()
    try:
        cfg = Config(a.target, proxy=a.proxy, verify_ssl=not a.no_verify, cmd=a.cmd)
        r = ExamplePoC(cfg).run(a.check_only)
        print(f"Result: {r.msg}" + (f" | Data: {r.data}" if r.data else ""))
        sys.exit(0 if r.success else 1)
    except ValueError as e:
        log.error(e); sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
