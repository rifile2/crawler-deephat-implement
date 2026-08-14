from crawler.hellhound_runner import HellhoundRunner
from config import HELLHOUND_DIR, CRAWL_OUTPUT
from crawler.parser import CrawlParser
from llm.deephat import DeepHat
from llm.prompts import PromptBuilder
from analysis.context_builder import ContextBuilder
from orchestrator.planner import Planner

from agents.sql_agent import SQLAgent
from agents.xss_agent import XSSAgent
from agents.authz_agent import AuthZAgent
from agents.password_policy_agent import PasswordPolicyAgent
from agents.nosql_agent import NoSQLAgent

# SAST temporarily disabled
# from agents.sast_agent import SASTAgent


def main():

    url = input("Enter Target URL: ").strip()

    # ----------------------------------------------------
    # SAST temporarily disabled
    # SAST requires a local source-code/project path.
    # source_path = input(
    #     "Enter Source Code Path for SAST (leave empty to skip): "
    # ).strip()
    # ----------------------------------------------------

    runner = HellhoundRunner(
        HELLHOUND_DIR,
        CRAWL_OUTPUT
    )

    success = runner.run(url)

    if success:

        print("\nCrawl Completed Successfully.")

        parser = CrawlParser(CRAWL_OUTPUT)
        parser.load()

        context = parser.build_context()

        print(type(context["endpoints"]))
        print(context["endpoints"][:2])

        builder = ContextBuilder(context)
        optimized_context = builder.build()

        print("\n========== RAW ENDPOINTS ==========\n")
        print(context.get("endpoints"))

        print("\nParsed Context Built Successfully.")

        prompt_builder = PromptBuilder(optimized_context)
        prompt = prompt_builder.build()

        print("\nPrompt Generated Successfully.")
        print(f"Prompt Size : {len(prompt)} characters")

        ai = DeepHat()

        print("\nAnalyzing with DeepHat...\n")

        report = ai.analyze(prompt)

        print(report)

        print("\n========== POTENTIAL VULNERABILITIES ==========\n")

        for item in optimized_context["potential_vulnerabilities"]:
            print(item)

        planner = Planner(optimized_context)

        execution_plan = planner.build_execution_plan()

        # ----------------------------------------------------
        # SAST temporarily disabled
        #
        # if source_path:
        #     execution_plan.append({
        #         "agent": "sast_agent",
        #         "endpoint": source_path
        #     })
        # ----------------------------------------------------

        print("\n========== EXECUTION PLAN ==========\n")

        for item in execution_plan:
            print(item)

        agent_results = []

        # To avoid running XSS multiple times
        xss_completed = False

        # To avoid running NoSQL multiple times
        nosql_completed = False

        # ----------------------------------------------------
        # SAST temporarily disabled
        # sast_completed = False
        # ----------------------------------------------------

        for item in execution_plan:

            # ---------------- SQL Agent ----------------

            if item["agent"] == "sql_agent":

                print("\nRunning SQL Agent...\n")

                sql = SQLAgent()

                result = sql.scan(
                    item["endpoint"]
                )

                agent_results.append({
                    "agent": "SQL Agent",
                    "endpoint": item["endpoint"],
                    "result": result
                })

            # ---------------- XSS Agent ----------------

            elif item["agent"] == "xss_agent":

                # XSS scans the full Spider JSON only once
                if not xss_completed:

                    print("\nRunning XSS Agent...\n")

                    xss = XSSAgent()

                    result = xss.scan(
                        CRAWL_OUTPUT
                    )

                    agent_results.append({
                        "agent": "XSS Agent",
                        "input": CRAWL_OUTPUT,
                        "result": result
                    })

                    xss_completed = True

            # ---------------- Password Policy Agent ----------------

            elif item["agent"] == "password_policy_agent":

                print("\nRunning Password Policy Agent...\n")

                password = PasswordPolicyAgent()

                result = password.scan(
                    optimized_context["target"]
                )

                agent_results.append({
                    "agent": "Password Policy Agent",
                    "result": result
                })

            # ---------------- Authorization Agent ----------------

            elif item["agent"] == "authz_agent":

                print("\nRunning Authorization Agent...\n")

                authz = AuthZAgent()

                result = authz.scan(
                    optimized_context["target"],
                    context["endpoints"]
                )

                agent_results.append({
                    "agent": "Authorization Agent",
                    "result": result
                })

            # ---------------- NoSQL Agent ----------------

            elif item["agent"] == "nosql_agent":

                if not nosql_completed:

                    print("\nRunning NoSQL Injection Agent...\n")

                    nosql = NoSQLAgent()

                    result = nosql.scan(
                        optimized_context["target"]
                    )

                    agent_results.append({
                        "agent": "NoSQL Injection Agent",
                        "result": result
                    })

                    nosql_completed = True

            # ----------------------------------------------------
            # SAST Agent temporarily disabled
            #
            # elif item["agent"] == "sast_agent":
            #
            #     if not sast_completed:
            #
            #         print("\nRunning SAST Agent...\n")
            #
            #         sast = SASTAgent()
            #
            #         source_path = item["endpoint"]
            #
            #         if source_path:
            #
            #             result = sast.scan(
            #                 source_path
            #             )
            #
            #             agent_results.append({
            #                 "agent": "SAST Agent",
            #                 "input": source_path,
            #                 "result": result
            #             })
            #
            #         else:
            #
            #             print(
            #                 "SAST skipped: no source-code path provided."
            #             )
            #
            #         sast_completed = True
            # ----------------------------------------------------

        print("\n========== AGENT RESULTS ==========\n")

        for result in agent_results:
            print(result)

    else:

        print("\nCrawl Failed.")


if __name__ == "__main__":
    main()