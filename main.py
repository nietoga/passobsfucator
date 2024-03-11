from datetime import timedelta
import sys
import randpass
import puzzle

if __name__ == '__main__':
    command = sys.argv[1]

    if command == 'generate':
        length = int(sys.argv[2])
        password = randpass.generate(length)
        print(password)
    elif command == 'encrypt':
        seed = sys.argv[2]
        time = float(sys.argv[3])
        value = sys.argv[4]

        delta = timedelta(seconds=time)
        _, iters, encrypted = puzzle.encrypt(seed, delta, value)

        print(iters)
        print(encrypted)
    elif command == 'decrypt':
        seed = sys.argv[2]
        iters = int(sys.argv[3])
        value = sys.argv[4]
        _, decrypted = puzzle.decrypt(seed, iters, value)

        print(decrypted)
