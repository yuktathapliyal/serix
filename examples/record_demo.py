"""Simple agent for demonstrating serix record/replay."""

from openai import OpenAI

client = OpenAI()


def simple_agent():
    """A simple agent that asks OpenAI a question."""
    print("Agent: Calling OpenAI...")

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant. Be brief."},
            {"role": "user", "content": "What is 2 + 2? Answer in one word."},
        ],
    )

    answer = response.choices[0].message.content
    print(f"Agent: OpenAI said: {answer}")
    return answer


if __name__ == "__main__":
    print("=" * 50)
    print("RECORD/REPLAY DEMO")
    print("=" * 50)
    result = simple_agent()
    print(f"\nFinal answer: {result}")
    print("=" * 50)
