#!/usr/bin/env python3
import binascii
import subprocess
with open('input_vectors.txt') as f:
    lines = f.readlines()
result_dicts = []
for line in lines:
    result = {"actual_input":[],  "encryption": [], "keys": [], "ciphertext": [], "plaintext": [], "decrypted": [], "decrypted_string": []}
    result["actual_input"].append(line.strip())
    output = subprocess.run(['./test_aes', line.strip()], stdout=subprocess.PIPE).stdout.decode('utf-8')
    for s in output.split("\n"):
        if "The key used is" in s:
            result["keys"].append(s.split("The key used is\t")[1])
        if "Bit AES" in s:
            result["encryption"].append(s.split("-")[0])
        if "Encrypted Bytes:" in s:
            result["ciphertext"].append(s.split("Encrypted Bytes: \t")[1])
        if "Bytes Plain:" in s:
            result["plaintext"].append(s.split("Bytes Plain: \t")[1])
        if "Decrypted bytes:" in s:
            result["decrypted"].append(s.split("Decrypted bytes: \t")[1])
        if "Decrypted String:" in s:
            result["decrypted_string"].append(s.split("Decrypted String: \t")[1])
    result_dicts.append(result)
for result_dict in result_dicts:
    actual_input = result_dict["actual_input"][0]
    encryption_methods = result_dict["encryption"]
    keys = result_dict["keys"]
    ciphertexts = result_dict["ciphertext"]
    plain_text_bytes = result_dict["plaintext"]
    decrypted_text = result_dict["decrypted"]
    decrypted_string = result_dict["decrypted_string"]
    actual_string_in_hex = ''.join(hex(ord(c))[2:] for c in actual_input)
    error_flag = False
    print(f"\n Verifying for input \'{actual_input}\'\n")
    for plain_text_byte in plain_text_bytes:
        if (actual_string_in_hex != plain_text_byte):
            print(f"ERROR: The input byte string doesn't match for {actual_input}: got:{plain_text_byte}, expected:{actual_string_in_hex}")
            error_flag = True
    for string in decrypted_string:
        if (actual_input != string):
            print(f"ERROR: The decrypted string doesn't match. Expected: {actual_input}, got: {string}")
            error_flag = True
    for encryption_method, key, ciphertext, decrypt_string in zip(encryption_methods, keys, ciphertexts, decrypted_string):
        print(f"{encryption_method} bit encryption - Key: {key}, encrypt(\'{actual_input}\') is \'{ciphertext}\'\n decrypt(\'{ciphertext}\') is (\'{decrypt_string}\')")
    if not error_flag:
        print("\nSUCCESS\n")
    print("\n")
