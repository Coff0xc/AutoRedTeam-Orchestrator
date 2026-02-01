"""
CVE相关工具模块

包含工具:
- cve_search: CVE实时搜索
- cve_detail: CVE详细信息
- cve_recent: 最近发布的CVE
"""

from datetime import datetime, timedelta

import requests


def register_cve_tools(mcp):
    """注册CVE相关工具到MCP服务器"""

    @mcp.tool()
    def cve_search(keyword: str, year: str = None, source: str = "all") -> dict:
        """CVE实时搜索 - 从多个数据源搜索最新漏洞信息

        Args:
            keyword: 搜索关键词 (如 wordpress, apache, spring)
            year: 筛选年份 (如 2024, 2025)
            source: 数据源 (nvd/github/circl/all)
        """
        results = []
        errors = []

        # 1. NVD (National Vulnerability Database) - 官方数据源
        if source in ["nvd", "all"]:
            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
                resp = requests.get(nvd_url, timeout=15, headers={"User-Agent": "AutoRedTeam/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("vulnerabilities", [])[:15]:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        if year and year not in cve_id:
                            continue

                        # 获取CVSS分数
                        cvss = "N/A"
                        metrics = cve.get("metrics", {})
                        if metrics.get("cvssMetricV31"):
                            cvss = (
                                metrics["cvssMetricV31"][0]
                                .get("cvssData", {})
                                .get("baseScore", "N/A")
                            )
                        elif metrics.get("cvssMetricV30"):
                            cvss = (
                                metrics["cvssMetricV30"][0]
                                .get("cvssData", {})
                                .get("baseScore", "N/A")
                            )

                        # 获取描述
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:200]
                                break

                        results.append(
                            {
                                "cve_id": cve_id,
                                "source": "NVD",
                                "cvss": cvss,
                                "summary": desc,
                                "published": cve.get("published", "")[:10],
                            }
                        )
            except Exception as e:
                errors.append(f"NVD: {str(e)}")

        # 2. GitHub Advisory Database
        if source in ["github", "all"]:
            try:
                gh_url = f"https://api.github.com/advisories?keyword={keyword}&per_page=15"
                resp = requests.get(
                    gh_url,
                    timeout=15,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "User-Agent": "AutoRedTeam/2.0",
                    },
                )
                if resp.status_code == 200:
                    for item in resp.json()[:10]:
                        cve_id = item.get("cve_id") or item.get("ghsa_id", "")
                        if year and year not in str(item.get("published_at", "")):
                            continue

                        severity = item.get("severity", "unknown").upper()
                        cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(
                            severity, "N/A"
                        )

                        results.append(
                            {
                                "cve_id": cve_id,
                                "source": "GitHub",
                                "cvss": cvss,
                                "severity": severity,
                                "summary": item.get("summary", "")[:200],
                                "published": item.get("published_at", "")[:10],
                            }
                        )
            except Exception as e:
                errors.append(f"GitHub: {str(e)}")

        # 3. CVE.circl.lu (备用)
        if source in ["circl", "all"] and len(results) < 5:
            try:
                circl_url = f"https://cve.circl.lu/api/search/{keyword}"
                resp = requests.get(circl_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data[:10]:
                        cve_id = item.get("id", "")
                        if year and year not in cve_id:
                            continue
                        if not any(r["cve_id"] == cve_id for r in results):  # 去重
                            results.append(
                                {
                                    "cve_id": cve_id,
                                    "source": "CIRCL",
                                    "cvss": item.get("cvss", "N/A"),
                                    "summary": item.get("summary", "")[:200],
                                }
                            )
            except Exception as e:
                errors.append(f"CIRCL: {str(e)}")

        # 按CVSS分数排序
        def get_cvss(x):
            try:
                return float(x.get("cvss", 0))
            except Exception:
                return 0

        results.sort(key=get_cvss, reverse=True)

        return {
            "success": True,
            "keyword": keyword,
            "year_filter": year,
            "results": results[:20],
            "total": len(results),
            "sources_queried": source,
            "errors": errors if errors else None,
        }

    @mcp.tool()
    def cve_detail(cve_id: str) -> dict:
        """获取CVE详细信息 - 包括漏洞描述、CVSS、受影响版本、参考链接"""
        try:
            # 从NVD获取详细信息
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(nvd_url, timeout=15, headers={"User-Agent": "AutoRedTeam/2.0"})

            if resp.status_code != 200:
                return {"success": False, "error": f"NVD API返回 {resp.status_code}"}

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"success": False, "error": f"未找到 {cve_id}"}

            cve = vulns[0].get("cve", {})

            # 解析CVSS
            cvss_info = {}
            metrics = cve.get("metrics", {})
            if metrics.get("cvssMetricV31"):
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_info = {
                    "version": "3.1",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                }

            # 解析描述
            description = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            # 解析受影响产品
            affected = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            affected.append(match.get("criteria", ""))

            # 解析参考链接
            references = []
            for ref in cve.get("references", [])[:10]:
                references.append({"url": ref.get("url"), "tags": ref.get("tags", [])})

            return {
                "success": True,
                "cve_id": cve_id,
                "description": description,
                "cvss": cvss_info,
                "published": cve.get("published", "")[:10],
                "modified": cve.get("lastModified", "")[:10],
                "affected_products": affected[:10],
                "references": references,
                "weaknesses": [
                    w.get("description", [{}])[0].get("value") for w in cve.get("weaknesses", [])
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def cve_recent(days: int = 7, severity: str = None) -> dict:
        """获取最近发布的CVE漏洞

        Args:
            days: 最近几天 (默认7天)
            severity: 严重性筛选 (CRITICAL/HIGH/MEDIUM/LOW)
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        try:
            nvd_url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
                f"pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}&"
                f"pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.999')}&"
                f"resultsPerPage=50"
            )

            resp = requests.get(nvd_url, timeout=20, headers={"User-Agent": "AutoRedTeam/2.0"})

            if resp.status_code != 200:
                return {"success": False, "error": f"NVD API返回 {resp.status_code}"}

            data = resp.json()
            results = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})

                # 获取CVSS
                cvss_score = 0
                cvss_severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                if metrics.get("cvssMetricV31"):
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")

                # 严重性筛选
                if severity and cvss_severity != severity.upper():
                    continue

                # 获取描述
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:150]
                        break

                results.append(
                    {
                        "cve_id": cve.get("id"),
                        "cvss": cvss_score,
                        "severity": cvss_severity,
                        "summary": desc,
                        "published": cve.get("published", "")[:10],
                    }
                )

            # 按CVSS排序
            results.sort(key=lambda x: x.get("cvss", 0), reverse=True)

            return {
                "success": True,
                "period": f"最近{days}天",
                "severity_filter": severity,
                "results": results[:30],
                "total": len(results),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    return ["cve_search", "cve_detail", "cve_recent"]
