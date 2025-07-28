import os
import sys
import clr
import pefile
import base64

# Add dnlib reference
dnlib_dll_path = os.path.join(os.path.dirname(__file__), "dnlib")
clr.AddReference(dnlib_dll_path)

# Import dnlib modules
import dnlib
from dnlib.DotNet import ModuleDef, ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet.Writer import ModuleWriterOptions

# Import reflection modules
from System import Int32, Type, Activator
from System.Reflection import Assembly, BindingFlags, MethodInfo

class StringDecryptor:
	# Target decryption functions to invoke
	DECRYPTION_METHOD_SIGNATURES = {
		"Parameters": ["System.String", "System.Int32", "System.Int32", "System.Int32", "System.Int32", "System.Int32"],
		"ReturnType": "System.String"
	}

	def __init__(self, file_path) -> None:
		self.file_path: str = file_path
		self.file_module: ModuleDefMD = ModuleDefMD.Load(file_path)
		self.file_assembly: Assembly = Assembly.LoadFrom(file_path)

		# Suspected methods and their corresponding signatures and invoke methods
		self.suspected_methods: dict[ModuleDef, tuple[str, MethodInfo]] = {}
		# Decrypted strings
		self.decrypted_strings: list[str] = []


	# Map suspected method names to their corresponding signatures and MethodInfo objects
	def search_method(self, name):
		# Search for static, public and non public members
		eFlags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic

		for module_type in self.file_assembly.GetTypes():
			for method in module_type.GetMethods(eFlags):
				if method.Name == name:
					return method

	def get_encryption_variables(self, insn, paramType):
		result = 0
		try:
			# Invoke suspected method
			target_method_ref = insn.Operand
			method_to_invoke = self.search_method(target_method_ref.Name)

			type_to_invoke = self.file_assembly.GetType(target_method_ref.DeclaringType.FullName)
			if not type_to_invoke:
				print(f"Could not load type '{target_method_ref.DeclaringType.FullName}' via Reflection.")
			else:
				if not method_to_invoke:
					print(f"Could not find method '{target_method_ref.Name}' via Reflection.")
				else:
					instance = None
					if not method_to_invoke.IsStatic:
						print("Method is not static. Creating an instance of the class...")
						# This creates an instance of the class using its default constructor
						instance = Activator.CreateInstance(type_to_invoke)

					result = method_to_invoke.Invoke(instance, None)
					
		except Exception as e:
			print(f"An error occurred during reflection/invocation: {e}")
		
		return result

	def decrypt_string(self, encrypted_buffer, key):
		decrypted_string = ""
		for char in encrypted_buffer:
			decrypted_string = decrypted_string + chr(ord(char) - key)
		
		return decrypted_string

	# Invoke all references to suspected methods
	def decrypt_strings(self, method_name):
		
		for module_type in self.file_module.Types:
			if not module_type.HasMethods:
				continue

			for method in module_type.Methods:
				if not method.HasBody:
					continue

				# Loop through method instructions
				for insnIdx, insn in enumerate(method.Body.Instructions):
					# Find Call instructions
					if insn.OpCode == OpCodes.Call:
						if method_name in str(insn.Operand):
							key = 0
							encrypted_buffer = ""
							# Get method parameters in reverse order
							for i in range(len(self.DECRYPTION_METHOD_SIGNATURES["Parameters"])):
								if i == 3:
									# Get integer
									key = self.get_encryption_variables(
										method.Body.Instructions[insnIdx - i - 1],
										self.DECRYPTION_METHOD_SIGNATURES["Parameters"][-i - 1])
								elif i == 5:
									encrypted_buffer = self.get_encryption_variables(
										method.Body.Instructions[insnIdx - i - 1],
										self.DECRYPTION_METHOD_SIGNATURES["Parameters"][-i - 1])

							
							result = base64.b64decode(self.decrypt_string(encrypted_buffer, key).encode("ascii")).decode("ascii")

							# Patch suspected method parameters with NOPs
							for i in range(len(self.DECRYPTION_METHOD_SIGNATURES["Parameters"])):
								method.Body.Instructions[insnIdx - i - 1].OpCode = OpCodes.Nop

							# Patch suspected method call with the result string
							method.Body.Instructions[insnIdx].OpCode = OpCodes.Ldstr
							method.Body.Instructions[insnIdx].Operand = result
							self.decrypted_strings.append(result)
							

	# Save the cleaned module to disk
	def save_module(self):
		# Add writer options to ignore dnlib errors
		options = ModuleWriterOptions(self.file_module)
		options.Logger = dnlib.DotNet.DummyLogger.NoThrowInstance

		# Build cleaned file name
		split_name = self.file_path.rsplit(".", 1)
		if len(split_name) == 1:
			cleaned_filename = "{0}_cleaned".format(*split_name)
		else:
			cleaned_filename = "{0}_cleaned.{1}".format(*split_name)

		# Write cleaned module content
		self.file_module.Write(cleaned_filename, options)


def main():
	if len(sys.argv) < 2:
		sys.exit("[!] Usage: dotnet_string_decryptor.py <dotnet_file_path>")

	file_path = sys.argv[1]

	# Check if the file exists
	if not os.path.exists(file_path):
		sys.exit("[-] File not found")

	# Use absolute file path
	if not os.path.isabs(file_path):
		file_path = os.path.abspath(file_path)

	# Check if the file is a valid PE
	try:
		pe = pefile.PE(file_path)
	except:
		sys.exit("[-] Invalid PE file")

	# Check if the file is .NET
	dotnet_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'] # COM descriptor table index
	if pe.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_dir].VirtualAddress == 0:
		sys.exit("[-] File is not .NET")

	decryptor = StringDecryptor(file_path)

	decryptor.decrypt_strings("puyogeg")
	decryptor.save_module()

	# Print decrypted strings list
	print("\n".join(decryptor.decrypted_strings))


if __name__ == "__main__":
	main()