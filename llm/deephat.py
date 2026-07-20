import subprocess


class DeepHat:

    def __init__(self):
        self.model = "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M"

    def analyze(self, prompt: str):

        print(f"\nPrompt Size: {len(prompt)} characters\n")

        process = subprocess.run(
            [
                "ollama",
                "run",
                self.model
            ],
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        print("Return Code:", process.returncode)
        print("STDERR:")
        print(process.stderr)

        return process.stdout