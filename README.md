# What is it?

A tool to encrypt plain text data with a time lock. I created it to obsfucate my LoL password, in order to avoid playing it without necessarily losing access to my account or e-mail.

# How to use it

Here are some examples of how to use it.

## Generate password

```bash
python main.py generate-password --length 10
```

## Encrypt a password

```bash
python main.py encrypt 'Q7w"RjF5v?' --time-in-seconds 10 --output-file encrypted.txt
```

Keep in mind:
* Encryption will take the same amount of time that decryption would take.

## Decrypt a password

```bash
python main.py decrypt encrypted.txt --output-file decrypted.txt
```

## A quick demo

```bash
# Generate password and store in a file
python main.py generate-password --length 10 > pass.txt
# Encrypt password. Change time-in-seconds to something more appropriate
python main.py encrypt "$(cat pass.txt)" --time-in-seconds 10 --output-file encrypted.txt
# Delete the raw password file
rm pass.txt

# Use the upcoming commands to decrypt it later
python main.py decrypt encrypted.txt --output-file decrypted.txt
cat decrypted.txt
```
