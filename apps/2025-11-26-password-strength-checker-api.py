import string
import re
import math
from collections import Counter
from functools import lru_cache

def check_password_strength(password):
    score = 0
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    elif len(password) < 12:
        score += 1
    else:
        score += 2

    # Check character types
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    if not (has_uppercase and has_lowercase and has_digit and has_special):
        feedback.append("Password should contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
    else:
        score += 2

    # Check for common patterns
    if is_common_password(password):
        feedback.append("Password is too common and easily guessable.")
    else:
        score += 1

    # Check entropy
    entropy = calculate_entropy(password)
    if entropy < 40:
        feedback.append("Password has low entropy and may be easily cracked.")
    elif entropy < 50:
        score += 1
    else:
        score += 2

    return score, feedback

@lru_cache(maxsize=1000)
def is_common_password(password):
    with open("common_passwords.txt", "r") as f:
        common_passwords = [line.strip() for line in f]
    return password in common_passwords

def calculate_entropy(password):
    char_counts = Counter(password)
    total_chars = sum(char_counts.values())
    entropy = 0
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
    return entropy

def main():
    password = input("Enter a password: ")
    score, feedback = check_password_strength(password)
    print(f"Password strength score: {score}/5")
    for message in feedback:
        print(f"- {message}")

if __name__ == "__main__":
    main()