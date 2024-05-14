import argparse
import json
import re


def remove_leading_junk_bytes(list):
	pattern_1 = bytearray([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x4B, 0x68, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48])
	pattern_length = len(pattern_1)
	pattern_found = False
	final_list = bytearray()

	total_counter = 0
	pattern_counter = 0
	for item in list:
		total_counter = total_counter + 1
		if item == pattern_1[pattern_counter]:
			pattern_counter = pattern_counter + 1
			if pattern_length == pattern_counter:
				pattern_found = True
				break
		else:
			pattern_counter = 0
		
	
	if pattern_found:
		for i in range(total_counter, len(list)):
			final_list.append(list[i])
	else:
		final_list = remove_leading_null_bytes(list)
	
	return final_list


def remove_leading_null_bytes(list):
	limit = 0
	for i in range(0, len(list) - 1):
		if list[i] != 0:
			limit = i
			break

	return list[limit:]


def remove_trailing_null_bytes(list):
	limit = 0
	for i in range(0, len(list) - 1):
		if list[i] == 0 and list[i + 1] == 0:
			limit = i
			break

	return list[0:limit]


def search_encrypted_conf(binary_path):
	encrypted_conf = bytearray()
	encrypted_conf_candidates = []
	pattern = rb"\x00[\x01-\xFF]{250,400}\x00{500}"

	with open(binary_path, "rb") as binary:
		bytes = binary.read()
		matches = re.findall(pattern, bytes)
		for match in matches:
			encrypted_conf = remove_leading_junk_bytes(match)
			encrypted_conf = remove_trailing_null_bytes(encrypted_conf)
			encrypted_conf_candidates.append(encrypted_conf)

	return encrypted_conf_candidates


def decrypt_key(encrypted_key):
	decrypted_key = []
	key_length = len(encrypted_key)

	for i in range(0, key_length):
		decrypted_key.append(ord(encrypted_key[i]) ^ (key_length - i))
	
	return decrypted_key


def decrypt_conf(encrypted_conf, encrypted_key):
	decrypted_conf = ""
	encrypted_conf_len = len(encrypted_conf)
	key = decrypt_key(encrypted_key)
	key_len = len(key)

	key_index = 0
	for index in range(0, encrypted_conf_len):
		decrypted_conf = decrypted_conf + chr(key[key_index] ^ encrypted_conf[index])
		key_index = (key_index + key[key_index]) % key_len
	
	return decrypted_conf


def extract_conf(encrypted_conf_candidates, encrypted_key):
	decrypted_conf = None
	for encrypted_conf in encrypted_conf_candidates:
		possible_conf = decrypt_conf(encrypted_conf, encrypted_key)
		if "0=" in possible_conf or "1=" in possible_conf:
			decrypted_conf = possible_conf
			break

	return decrypted_conf


def map_conf(conf):
	mapped_conf = {}
	flag_mapping = {
			"0": "command_and_control",
			"1": "persistence",
			"2": "unknown_2",
			"3": "anti_vm_1",
			"4": "min_disk",
			"5": "check_xeon",
			"6": "anti_vm_2",
			"7": "check_ram",
			"8": "fake_error",
			"9": "unknown_9",
			"10": "unknown_10",
			"11": "fake_error_title",
			"12": "base64_fake_error_msg",
			"13": "unknown_13",
			"14": "unknown_14",
			"15": "port",
			"16": "unknown_16",
			"17": "unknown_17",
			"18": "min_disk",
			"19": "min_ram",
			"20": "unknown_20",
			"21": "unknown_21",
			"22": "crypter_dll",
			"23": "crypter_au3",
			"24": "unknown_24",
			"25": "user",
			"26": "relaunch_process_hollowing",
			"27": "xor_key",
			"28": "unknown_28",
			"29": "dll_sideloading_method",
			"30": "unknown_30",
			"31": "crypter_ahk",
			"32": "av_bypass",
			"33": "crypter_sqlite3_dll",
		}
	
	for item in re.findall(r"(\d+|tabla)=([^\r\n]+)", conf):
			if item[0] in flag_mapping:
				mapped_conf[flag_mapping[item[0]]] = item[1]
			else:
				mapped_conf[item[0]] = item[1]
	
	return mapped_conf


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("file")
	parser.add_argument(
		"-p",
		"--password",
		required=False,
		default="ckcilIcconnh",
		action="store",
		help="The password to be used to decrypt de malware, if no option is provided the default one will be used 'ckcilIcconnh'.",
	)
	parser.add_argument(
		"-m",
		"--map",
		required=False,
		action="store_true",
		help="If enabled, it will map the different items of the extracted configuration.",
	)

	args = parser.parse_args()

	encrypted_conf_candidates = search_encrypted_conf(args.file)
	decrypted_conf = extract_conf(encrypted_conf_candidates, args.password)
	
	if decrypted_conf:
		print("[+] The configuration has been successfully extacted!!\n")

		if args.map:
			print(json.dumps(map_conf(decrypted_conf)))
		else:
			print(decrypted_conf)
	else:
		print("[-] No configuration could be extracted\n")
