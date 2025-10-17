import os
import sys
import subprocess
import argparse
import shutil
import tempfile
import re
import json
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

class CodeFormatterHook:
    def __init__(self, config_path: Optional[str] = None):
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.formatters = {
            'python': {
                'black': ['black', '--check', '--diff'],
                'isort': ['isort', '--check', '--diff'],
                'flake8': ['flake8'],
                'mypy': ['mypy']
            },
            'javascript': {
                'prettier': ['prettier', '--check'],
                'eslint': ['eslint']
            }
        }

    def _setup_logging(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        default_config = {
            'formatters': {
                'python': ['black', 'isort', 'flake8', 'mypy'],
                'javascript': ['prettier', 'eslint']
            },
            'ignore_paths': ['.git', 'venv', 'node_modules'],
            'max_file_size': 1024 * 1024  # 1MB
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except json.JSONDecodeError:
                self.logger.warning(f"Invalid config file: {config_path}")

        return default_config

    def _should_ignore_path(self, path: str) -> bool:
        return any(ignore_path in path for ignore_path in self.config.get('ignore_paths', []))

    def _get_staged_files(self) -> List[str]:
        try:
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
                capture_output=True, text=True, check=True
            )
            return [f for f in result.stdout.splitlines() if not self._should_ignore_path(f)]
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting staged files: {e}")
            return []

    def _run_formatter(self, formatter: str, files: List[str]) -> Tuple[bool, str]:
        try:
            cmd = self.formatters['python'].get(formatter, [formatter])
            result = subprocess.run(
                [*cmd, *files],
                capture_output=True, text=True
            )
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)

    def run_pre_commit_checks(self) -> bool:
        staged_files = self._get_staged_files()
        if not staged_files:
            self.logger.info("No staged files to check.")
            return True

        python_files = [f for f in staged_files if f.endswith('.py')]
        js_files = [f for f in staged_files if f.endswith('.js')]

        all_checks_passed = True

        for formatter in self.config['formatters']['python']:
            if python_files:
                success, output = self._run_formatter(formatter, python_files)
                if not success:
                    self.logger.error(f"{formatter} check failed:\n{output}")
                    all_checks_passed = False

        for formatter in self.config['formatters']['javascript']:
            if js_files:
                success, output = self._run_formatter(formatter, js_files)
                if not success:
                    self.logger.error(f"{formatter} check failed:\n{output}")
                    all_checks_passed = False

        return all_checks_passed

def main():
    parser = argparse.ArgumentParser(description='Pre-commit code formatting and linting hook')
    parser.add_argument('--config', help='Path to configuration file', default=None)
    args = parser.parse_args()

    hook = CodeFormatterHook(args.config)
    result = hook.run_pre_commit_checks()
    sys.exit(0 if result else 1)

if __name__ == '__main__':
    main()