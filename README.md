# pwdcheck

small utility that criticizes your password choices (for the sake of security!)

## Introduction

`pwdcheck` is an opinionated password checkup utility and generator that consumes a potential
password you want to use, actively judges it against some criteria, and uses a Pwdhhash-inspired deterministic password generation scheme to create a unique and secure password you can use (TODO: automate the input process into forms, like PwdHash does).

## Design

### Checkup Flow

The _checkup flow_ contains the following steps:

1. Password Strength - uses the zxcvbn to quantify password strength
2. Password Breach - checks against PwnedPassword's k-anonymized dataset.

### Password Derivation Scheme

WIP, but will most likely be using the built-in HKDF support for key generation, using several params:

* url base
* password
* username
* some type of token parsed from source to be like a HMAC

## Usage

To download and install:

```
$ go get -u github.com/ex0dus-0x/pwdcheck
```

## Questions

### Why check for presence in a breach if a better password is being generated anyways?

If such theft-resistant password derivation schemes become more prevalent, attackers might start
incorporating KDF schemes as part of the credential reuse campaign to derive potential permutations
of passwords for different services.
