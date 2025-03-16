# ADKeygen
Generate AES128/256 Kerberos keys and NTLM hash for an AD account.
```
usage: ADKeygen.py [-h] -domain DOMAIN -user USER -pass PASSWORD [-host]

Generate AES128/256 Kerberos keys and NTLM hash for an AD account

options:
  -h, --help      show this help message and exit
  -domain DOMAIN  EXAMPLE.COM
  -user USER      sAMAccountName - case sensitive for AD user accounts
  -pass PASSWORD  Valid cleartext or hex account password
  -host           Target is a computer account
```

# Example
```sh
$ python3 ADKeygen.py -domain EXAMPLE.COM -user tacticalgator -pass password123 
[*] Salt: EXAMPLE.COMtacticalgator

[+] AES256 Key: C8BE9141BDF816C4C8997371063BC047A31B5C6851D6B19012A228DA9CD13DD9
[+] AES128 Key: FE4EF53B876B60D0D515C4767AEF4492
[+] NTLM Hash:  A9FDFA038C4B75EBC76DC855DD74F0DA
```
