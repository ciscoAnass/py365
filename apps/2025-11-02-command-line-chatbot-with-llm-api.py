import os
import sys
import json
import requests
import threading
import time
from typing import List, Dict
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

class ChatbotConfig:
    def __init__(self):
        self.api_key = os.getenv('OPENAI_API_KEY', '')
        self.model = 'gpt-3.5-turbo'
        self.max_tokens = 150
        self.temperature = 0.7
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history_length = 10

class TerminalUI:
    def __init__(self):
        self.style = Style.from_dict({
            'prompt': '#ansigreen bold',
            'output': '#ansicyan',
            'error': '#ansired bold'
        })
        self.session = PromptSession(style=self.style)

    def display_welcome(self):
        print(HTML('<ansigreen>🤖 Welcome to AIChat - Your Intelligent Companion</ansigreen>').formatted_text)
        print(HTML('<ansiyellow>Type "/quit" to exit, "/clear" to reset conversation</ansiyellow>').formatted_text)

    def get_user_input(self) -> str:
        try:
            user_input = self.session.prompt(HTML('<ansigreen>You: </ansigreen>'))
            return user_input.strip()
        except KeyboardInterrupt:
            return '/quit'

    def display_response(self, response: str):
        print(HTML(f'<ansicyan>AI: {response}</ansicyan>').formatted_text)

    def display_error(self, message: str):
        print(HTML(f'<ansired>Error: {message}</ansired>').formatted_text)

class OpenAILanguageModel:
    def __init__(self, config: ChatbotConfig):
        self.config = config
        self.base_url = 'https://api.openai.com/v1/chat/completions'
        self.headers = {
            'Authorization': f'Bearer {self.config.api_key}',
            'Content-Type': 'application/json'
        }

    def generate_response(self, prompt: str) -> str:
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")

        self.config.conversation_history.append({"role": "user", "content": prompt})
        
        if len(self.config.conversation_history) > self.config.max_history_length:
            self.config.conversation_history = self.config.conversation_history[-self.config.max_history_length:]

        payload = {
            'model': self.config.model,
            'messages': self.config.conversation_history,
            'max_tokens': self.config.max_tokens,
            'temperature': self.config.temperature
        }

        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload)
            response.raise_for_status()
            result = response.json()
            ai_message = result['choices'][0]['message']['content'].strip()
            
            self.config.conversation_history.append({"role": "assistant", "content": ai_message})
            return ai_message

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"API request failed: {e}")

class AIAssistant:
    def __init__(self):
        self.config = ChatbotConfig()
        self.ui = TerminalUI()
        self.llm = OpenAILanguageModel(self.config)

    def run(self):
        self.ui.display_welcome()
        
        while True:
            try:
                user_input = self.ui.get_user_input()

                if user_input.lower() == '/quit':
                    print("Goodbye!")
                    break
                
                if user_input.lower() == '/clear':
                    self.config.conversation_history.clear()
                    self.ui.display_response("Conversation history cleared.")
                    continue

                response = self.llm.generate_response(user_input)
                self.ui.display_response(response)

            except Exception as e:
                self.ui.display_error(str(e))

def main():
    try:
        assistant = AIAssistant()
        assistant.run()
    except KeyboardInterrupt:
        print("\nProgram terminated.")
        sys.exit(0)

if __name__ == '__main__':
    main()