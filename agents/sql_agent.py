import requests
import time


class SQLAgent:
    """
    Active SQL Injection validation agent.

    Runs basic SQL injection payloads against
    a suspected endpoint and returns observations.
    """

    def __init__(self, timeout=10):

        self.timeout = timeout

        self.payloads = [

            "'",

            "' OR '1'='1",

            "' UNION SELECT NULL--",

            "' AND 1=1--",

            "' AND 1=2--"

        ]

        self.error_patterns = [

            "sql syntax",
            "mysql",
            "syntax error",
            "postgresql",
            "sqlite",
            "oracle",
            "odbc",
            "unclosed quotation",
            "database error",
            "sqlstate"

        ]

    def scan(self, endpoint):

        findings = []

        for payload in self.payloads:

            url = self.build_url(endpoint, payload)

            try:

                start = time.time()

                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )

                elapsed = time.time() - start

                body = response.text.lower()

                matched = []

                for pattern in self.error_patterns:

                    if pattern in body:
                        matched.append(pattern)

                findings.append({

                    "payload": payload,

                    "status_code": response.status_code,

                    "response_time": round(elapsed, 2),

                    "possible_sql_error": len(matched) > 0,

                    "matched_patterns": matched

                })

            except Exception as e:

                findings.append({

                    "payload": payload,

                    "error": str(e)

                })

        return findings

    def build_url(self, endpoint, payload):

        if "?" in endpoint:

            return endpoint + payload

        return endpoint + "?id=" + payload