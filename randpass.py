import string
import random

# From: https://www.geeksforgeeks.org/create-a-random-password-generator-using-python/
def generate(length: int) -> str:
    lowers = list(string.ascii_lowercase)
    uppers = list(string.ascii_uppercase)
    digits = list(string.digits)
    punctuations = list(string.punctuation)

    random.shuffle(lowers)
    random.shuffle(uppers)
    random.shuffle(digits)
    random.shuffle(punctuations)

    letterCount = round(length * (60 / 100))
    symbolNumberCount = length - letterCount

    result = []
    for _ in range(0, letterCount, 2):
        result.append(random.choice(lowers))
        result.append(random.choice(uppers))

    for _ in range(0, symbolNumberCount, 2):
        result.append(random.choice(digits))
        result.append(random.choice(punctuations))

    random.shuffle(result)
    return "".join(result)[:length]
