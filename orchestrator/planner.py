class Planner:

    """
    Decides which security agents should run
    based on DeepHat's potential vulnerabilities.
    """

    def __init__(self, context: dict):

        self.context = context

    def build_execution_plan(self):

        plan = []

        findings = self.context.get("potential_vulnerabilities", [])

        for finding in findings:

            vuln = finding.get("vulnerability", "").lower()

            endpoint = finding.get("endpoint", "")

            if "sql" in vuln:

                plan.append({
                    "agent": "sql_agent",
                    "endpoint": endpoint
                })

            elif "xss" in vuln:

                plan.append({
                    "agent": "xss_agent",
                    "endpoint": endpoint
                })

            elif "idor" in vuln:

                plan.append({
                    "agent": "idor_agent",
                    "endpoint": endpoint
                })

            elif "csrf" in vuln:

                plan.append({
                    "agent": "csrf_agent",
                    "endpoint": endpoint
                })

            elif "upload" in vuln:

                plan.append({
                    "agent": "upload_agent",
                    "endpoint": endpoint
                })

            elif "auth" in vuln:

                plan.append({
                    "agent": "auth_agent",
                    "endpoint": endpoint
                })

            elif "ssrf" in vuln:

                plan.append({
                    "agent": "ssrf_agent",
                    "endpoint": endpoint
                })

        return plan