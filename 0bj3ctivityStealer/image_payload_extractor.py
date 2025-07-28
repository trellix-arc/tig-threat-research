import io
import sys
from PIL import Image

# --- Configuration ---
# The binary file to read from.
INPUT_BINARY_FILE = './wp4096799-lost-in-space-wallpapers.jpg'
# The file where the extracted binary will be saved.
OUTPUT_BINARY_FILE = 'stage_2_binary.bin'
# The specific byte sequence to search for.
# This sequence looks like a BMP header: BM, size, reserved, offset, DIB header size.
SEQUENCE_TO_FIND = bytes([
	0x42, 0x4D, 0x32, 0x55, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00,
	0x00, 0x00, 0x28, 0x00
])

def main():
	"""
	Main function to execute the extraction logic.
	"""
	# 1. Read the binary file into image_buffer
	try:
		with open(INPUT_BINARY_FILE, 'rb') as f:
			image_buffer = f.read()
		print(f"[+] Successfully read {len(image_buffer)} bytes from '{INPUT_BINARY_FILE}'.")
	except FileNotFoundError:
		print(f"[-] Error: The input file '{INPUT_BINARY_FILE}' was not found.")
		sys.exit(1)

	# 2. Search for the byte sequence
	address = image_buffer.find(SEQUENCE_TO_FIND)

	# 3. If found, get the address and copy data to a new buffer
	if address == -1:
		print("[-] Error: The specified byte sequence was not found.")
		sys.exit(1)

	print(f"[+] Sequence found at offset (address): {hex(address)}")
	extracted_image_buffer = image_buffer[address:]

	# 4. Read the extracted buffer as an image and get RGB values
	rgb_buffer = []
	try:
		# Use io.BytesIO to treat the byte array like a file
		image_file = io.BytesIO(extracted_image_buffer)
		with Image.open(image_file) as img:
			img = img.convert("RGB") # Ensure image is in RGB format
			width, height = img.size
			print(f"[+] Image data parsed successfully ({width}x{height}).")

			# 5. Loop over each pixel to store RGB values sequentially
			for y in range(height):
				for x in range(width):
					r, g, b = img.getpixel((x, y))
					rgb_buffer.extend([r, g, b])
	except Exception as e:
		print(f"[-] Error processing image data from buffer: {e}")
		sys.exit(1)
		
	print(f"[+] Extracted {len(rgb_buffer)} RGB byte values into a buffer.")

	# 6. Read the first 4 elements of rgb_buffer to get the binary size
	if len(rgb_buffer) < 4:
		print("[-] Error: Not enough data in the RGB buffer to determine binary size.")
		sys.exit(1)

	size_bytes = bytes(rgb_buffer[0:4])
	binary_size = int.from_bytes(size_bytes, 'little')
	print(f"[+] Binary size determined from image data: {binary_size} bytes.")

	# 7. Store the binary in a binary file
	# The binary starts after the 4-byte size header and has a length of 'binary_size'
	start_index = 4
	end_index = start_index + binary_size
	
	if len(rgb_buffer) < end_index:
		print(f"[-] Error: RGB buffer is too small. Needed {end_index} bytes but only have {len(rgb_buffer)}.")
		sys.exit(1)
		
	binary_data = bytes(rgb_buffer[start_index:end_index])

	with open(OUTPUT_BINARY_FILE, 'wb') as f:
		f.write(binary_data)
		
	print(f"[+] Success! Extracted binary written to '{OUTPUT_BINARY_FILE}'.")


if __name__ == '__main__':
	main()