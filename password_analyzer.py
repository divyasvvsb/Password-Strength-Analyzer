"""Password Strength Analyzer
Features: length/complexity/uniqueness checks, stronger suggestions,
and reuse prevention using salted SHA-256 hashes (no plain-text storage).
"""
import hashlib
import math
import re
import secrets
import string

COMMON = {"password", "123456", "12345678", "qwerty", "abc123", "password1",
          "admin", "welcome", "iloveyou", "letmein", "india123", "test1234"}

# Simulated "database" of old passwords: {salt: hash}
OLD_PASSWORDS = {}


def hash_pw(pw, salt):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def save_password(pw):
    salt = secrets.token_hex(8)
    OLD_PASSWORDS[salt] = hash_pw(pw, salt)


def was_used_before(pw):
    return any(hash_pw(pw, s) == h for s, h in OLD_PASSWORDS.items())


def has_sequence(pw):
    low = pw.lower()
    for i in range(len(low) - 2):
        a, b, c = ord(low[i]), ord(low[i + 1]), ord(low[i + 2])
        if b - a == 1 and c - b == 1:
            return True
    return False


def entropy_bits(pw):
    pool = 0
    pool += 26 if re.search(r"[a-z]", pw) else 0
    pool += 26 if re.search(r"[A-Z]", pw) else 0
    pool += 10 if re.search(r"\d", pw) else 0
    pool += 32 if re.search(r"[^\w\s]", pw) else 0
    return len(pw) * math.log2(pool) if pool else 0


def suggest(n=3, length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    out = []
    while len(out) < n:
        p = "".join(secrets.choice(chars) for _ in range(length))
        if (re.search(r"[a-z]", p) and re.search(r"[A-Z]", p)
                and re.search(r"\d", p) and re.search(r"[!@#$%^&*]", p)):
            out.append(p)
    return out


def analyze(pw):
    score, feedback = 0, []

    # Length
    if len(pw) >= 12:
        score += 2
    elif len(pw) >= 8:
        score += 1
        feedback.append("Use 12+ characters.")
    else:
        feedback.append("Too short (minimum 8 characters).")

    # Complexity
    checks = [(r"[a-z]", "lowercase letter"), (r"[A-Z]", "uppercase letter"),
              (r"\d", "digit"), (r"[^\w\s]", "special character")]
    for pattern, name in checks:
        if re.search(pattern, pw):
            score += 1
        else:
            feedback.append(f"Add a {name}.")

    # Uniqueness
    if pw.lower() in COMMON:
        score -= 3
        feedback.append("This is a very common password.")
    if re.search(r"(.)\1{2,}", pw):
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times.")
    if has_sequence(pw):
        score -= 1
        feedback.append("Avoid sequences like 'abc' or '123'.")
    if was_used_before(pw):
        score -= 3
        feedback.append("You have used this password before. Choose a new one.")

    level = "Weak" if score <= 3 else "Medium" if score <= 5 else "Strong"
    return level, score, round(entropy_bits(pw), 1), feedback


if __name__ == "__main__":
    save_password("OldPass@2024")  # example of a previously used password
    while True:
        pw = input("\nEnter a password (or 'q' to quit): ")
        if pw == "q":
            break
        level, score, bits, feedback = analyze(pw)
        print(f"Strength: {level} | Score: {score} | Entropy: {bits} bits")
        for f in feedback:
            print(" -", f)
        if level != "Strong":
            print("Stronger suggestions:")
            for s in suggest():
                print("  ", s)
        else:
            save_password(pw)
            print("Password accepted and stored securely (salted hash).")
