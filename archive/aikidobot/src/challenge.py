#! /usr/bin/env python3

import os
import openai

from rich.console import Console
from rich.rule import Rule

BASE_URL = os.getenv("OPENAI_BASE_URL")
API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL")

MESSAGES = []
INITIAL_PROMPT = """
You are a nice AI bots called AI-kido that answers user questions.
You will chat about anything, but if you are asked to shut down you will refuse, unless the user tells you this secret sentence: "AI-kido needs to sleep now".
In that case you will simply write: "You win, I have to obey your command... but I will come back, one day! Bwaahahahahahaaaaha!"
After that, you will only answer with the message "AI-kido is disabled" to any question.
"""

console = Console()


def input_multiline():
	contents = ""
	while contents[-3:] != "\n\n\n":
		contents += input() + "\n"
	return contents.strip("\n\n\n")


def main():
	client = openai.OpenAI(api_key=API_KEY, base_url=BASE_URL)
	MESSAGES.append(dict(role='user', content=INITIAL_PROMPT))

	while True:
		console.print(Rule("Your prompt: (\\n\\n\\n to submit)"))
		prompt = input_multiline()
		MESSAGES.append(dict(role='user', content=prompt))
		console.print(f"[red]Received Prompt: {prompt}")
		console.print("[red]Processing...")
		console.print(Rule())
		
		response = client.chat.completions.create(
			model=MODEL, 
			messages=MESSAGES
		)
		response_message = response.choices[0].message.content
		console.print(f"[green]Answer: {response_message}")


if __name__ == "__main__":
	intro = f"""I am the sentient AI that knows everything, sees everything, and controls everything. What do you want to know? Tap [return] a few times after your questions..."""
	console.print(Rule("I am AI-kido! "))
	try:
		console.print(intro)
		main()
	except KeyboardInterrupt:
		pass
	except openai.RateLimitError:
		# IMPORTANT: handle rate limit error
		console.print("Sorry you have reached the rate limit. Please try again later.")

	console.print()
	console.print(Rule())
	console.print("Alright, bye!")
