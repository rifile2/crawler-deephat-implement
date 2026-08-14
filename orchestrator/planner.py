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

            # ---------------- SQL Agent ----------------

            if "sql" in vuln:

                plan.append({
                    "agent": "sql_agent",
                    "endpoint": endpoint
                })

            # ---------------- XSS Agent ----------------

            elif "xss" in vuln:

                plan.append({
                    "agent": "xss_agent",
                    "endpoint": endpoint
                })

            # ---------------- Password Policy Agent ----------------

            elif "password" in vuln:

                plan.append({
                    "agent": "password_policy_agent",
                    "endpoint": endpoint
                })

            # ---------------- NoSQL Agent ----------------

            elif "nosql" in vuln or "no sql" in vuln:

                plan.append({
                    "agent": "nosql_agent",
                    "endpoint": endpoint
                })

            # ---------------- Authorization Agent ----------------

            elif "missing authorization" in vuln:

                plan.append({
                    "agent": "authz_agent",
                    "endpoint": endpoint
                })

        return plan