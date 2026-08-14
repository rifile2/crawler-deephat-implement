class ContextBuilder:
    """
    Optimizes parsed crawl data before sending to DeepHat.
    """

    def __init__(self, context: dict):
        self.context = context

    def build(self):

        return {

            "target": self.context.get("target"),

            "summary": self.build_summary(),

            "interesting_endpoints": self.build_endpoints(),

            "security_findings": self.build_headers(),

            "potential_vulnerabilities": self.build_potential_vulnerabilities(),

            "technologies": self.build_technologies(),

            "waf": self.build_waf(),

            "statistics": self.build_statistics()

        }

    # ----------------------------------------------------

    def build_summary(self):

        summary = self.context.get("summary", {})

        return {
            "Total Endpoints": summary.get("total_endpoints", 0),
            "Header Issues": summary.get("header_issues", 0),
            "Secrets": summary.get("secrets", 0),
            "Sensitive Files": summary.get("sensitive_files_found", 0),
            "GraphQL": summary.get("graphql_exposed", 0),
            "OpenAPI": summary.get("openapi_exposed", 0),
            "WAF Detected": summary.get("waf_detected", False)
        }

    # ----------------------------------------------------

    def build_endpoints(self):

        important = []

        print("\nDEBUG ENDPOINTS:")
        print(self.context.get("endpoints"))

        keywords = [

            "login",
            "signin",
            "signup",
            "register",
            "admin",
            "dashboard",
            "panel",
            "auth",
            "oauth",
            "upload",
            "avatar",
            "image",
            "file",
            "api",
            "graphql",
            "rest",
            "payment",
            "checkout",
            "user",
            "profile",
            "account",
            "search",
            "query",
            "comment",
            "feedback",
            "review"

        ]

        for endpoint in self.context.get("endpoints", []):

            url = endpoint.get("url", "")

            if any(word in url.lower() for word in keywords):

                important.append(url)

        return sorted(list(set(important)))[:20]

    # ----------------------------------------------------

    def build_headers(self):

        findings = []

        for item in self.context.get("header_audit", []):

            findings.append(
                {
                    "severity": item.get("severity"),
                    "issue": item.get("issue")
                }
            )

        return findings

    # ----------------------------------------------------

    def build_technologies(self):

        return self.context.get("technologies", [])[:10]

    # ----------------------------------------------------

    def build_waf(self):

        waf = self.context.get("waf", [])

        if not waf:
            return "None"

        return waf[0].get("waf", "Unknown")

    # ----------------------------------------------------

    def build_potential_vulnerabilities(self):

        findings = []

        patterns = {

            # ====================================================
            # ACTIVE AGENT 1: SQL INJECTION
            # ====================================================

            "Potential SQL Injection": [
                "search",
                "?q=",
                "?query=",
                "?id=",
                "?product=",
                "?category=",
                "?page="
            ],

            # ====================================================
            # ACTIVE AGENT 2: XSS
            # ====================================================

            "Potential Cross-Site Scripting (XSS)": [
                "comment",
                "feedback",
                "review",
                "message",
                "contact",
                "chat"
            ],

            # ====================================================
            # ACTIVE AGENT 3: MISSING AUTHORIZATION
            # ====================================================

            "Potential Missing Authorization": [
                "admin",
                "dashboard",
                "manage",
                "panel",
                "/admin",
                "/api/admin",
                "/dashboard",
                "/manage",
                "profile",
                "user",
                "account"
            ],

            # ====================================================
            # ACTIVE AGENT 4: NOSQL INJECTION
            # ====================================================

            "Potential NoSQL Injection": [
                "?query=",
                "?filter=",
                "?search=",
                "?where=",
                "?find=",
                "?sort=",
                "?order=",
                "?username=",
                "?email=",
                "?user=",
                "mongo",
                "mongodb"
            ],

            # ====================================================
            # ACTIVE AGENT 5: PASSWORD POLICY
            # ====================================================

            "Potential Weak Password Policy": [
                "login",
                "signin",
                "signup",
                "register",
                "auth",
                "password",
                "forgot-password",
                "reset-password"
            ]

            # ====================================================
            # INACTIVE AGENTS - TEMPORARILY DISABLED
            # ====================================================

            # "Potential Authentication Weakness": [
            #     "login",
            #     "signin",
            #     "signup",
            #     "register",
            #     "auth",
            #     "oauth"
            # ],

            # "Potential File Upload": [
            #     "upload",
            #     "avatar",
            #     "image",
            #     "photo",
            #     "file",
            #     "attachment"
            # ],

            # "Potential IDOR": [
            #     "/user/",
            #     "/profile/",
            #     "/account/",
            #     "/api/user",
            #     "?user=",
            #     "?id="
            # ],

            # "Potential Admin Exposure": [
            #     "admin",
            #     "dashboard",
            #     "manage",
            #     "panel",
            #     "console"
            # ],

            # "Potential API Endpoint": [
            #     "/api/",
            #     "/graphql",
            #     "/rest/"
            # ]

        }

        endpoints = self.context.get("endpoints", [])

        print("\nDEBUG POTENTIAL ENDPOINTS")
        print(endpoints)

        seen = set()

        for endpoint in endpoints:

            print("DEBUG URL:", endpoint.get("url"))

            url = endpoint.get("url", "")

            lower = url.lower()

            for vuln, keywords in patterns.items():

                if any(k in lower for k in keywords):

                    key = (vuln, url)

                    if key not in seen:

                        findings.append({

                            "vulnerability": vuln,

                            "endpoint": url,

                            "confidence": "Medium",

                            "status": "Potential",

                            "validation": "Active penetration testing required"

                        })

                        seen.add(key)

        return findings[:20]

    # ----------------------------------------------------

    def build_statistics(self):

        stats = {

            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0

        }

        for finding in self.context.get("header_audit", []):

            sev = finding.get("severity", "").lower()

            if sev in stats:

                stats[sev] += 1

        return stats