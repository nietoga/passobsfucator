# What is it?

I'm trying to obsfucate a password with a time-lock in order to avoid playing League of Legends without necessarily losing my account.

# Example

Here's an example of how to use it:

## Generate password

Arguments: `<length>`

```
python main.py generate 10
B`Bxu+I1z7
```

## Encrypt a password

Arguments: `<seed> <duration of decription> <value>`

Keep in mind:
* Encryption will take the same amount of time it takes to decrypt.
* You can't forget the seed value or need to store it somewhere else.
* You need to store the resulting values somewhere. The first line is the number of iterations it took to generate the value. The second line is the encrypted value.

```
python main.py encrypt 1234 30 'B`Bxu+I1z7'
26432284
b'gAAAAABl71sK37AGmrBcHxd07aHNcwnK7eRam70VXWd2uYvMTs4L_aZIs6cOzlE2PCRA5sKdPzLvAXD-QPoGo0Z7Yi__h-vUeg=='
```

## Decrypt a password

Arguments: `<seed> <iterations> <encrypted-value>`

```
python main.py decrypt 1234 26432284 gAAAAABl71sK37AGmrBcHxd07aHNcwnK7eRam70VXWd2uYvMTs4L_aZIs6cOzlE2PCRA5sKdPzLvAXD-QPoGo0Z7Yi__h-vUeg==
b'B`Bxu+I1z7'
```

# Pending work

* I just noticed that type annotations in Python are not really strict. In particular, in the module `puzzle.py` I'm working with `bytes` as if they were `str`. They aren't, and that should be fixed.
