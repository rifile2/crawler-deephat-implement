from crawler.hellhound_runner import HellhoundRunner
from config import HELLHOUND_DIR, CRAWL_OUTPUT
from crawler.parser import CrawlParser
from llm.deephat import DeepHat
from llm.prompts import PromptBuilder
from analysis.context_builder import ContextBuilder
from orchestrator.planner import Planner
from agents.sql_agent import SQLAgent

def main():
    url = input("Enter Target URL: ").strip()

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

        builder = ContextBuilder(context)
        optimized_context = builder.build()

        print("\n========== RAW ENDPOINTS ==========\n")
        print(context.get("endpoints"))

        print("Parsed Context Built Successfully.")

        prompt_builder = PromptBuilder(optimized_context)
        prompt = prompt_builder.build()

        print(" Prompt Generated Successfully.")
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

        print("\n========== EXECUTION PLAN ==========\n")

        for item in execution_plan:

            print(item)


        agent_results = []

        for item in execution_plan:

            if item["agent"] == "sql_agent":

                print("\nRunning SQL Agent...\n")

                sql = SQLAgent()

                result = sql.scan(item["endpoint"])

                agent_results.append({

                    "agent": "SQL Agent",

                    "endpoint": item["endpoint"],

                    "result": result

                })

        print("\n========== AGENT RESULTS ==========\n")

        for result in agent_results:

            print(result)
    else:
        print("\nCrawl Failed.")


if __name__ == "__main__":
    main()