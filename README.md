🔐 Blockchain Wallet Key Encryptor PRO (AES-256)



A professional Python tool to encrypt and decrypt sensitive blockchain wallet files and folders using AES-256 encryption.
This project was developed as part of my internship to demonstrate practical knowledge in cyber security and ethical hacking.

 
👨‍💻 Developed By

Name: D.J. Ganesh

Intern ID: CITSOD227

Company: CodTech IT Solutions

Domain: Cyber Security & Ethical Hacking

Mentor: Neela Santosh

Internship Duration: 6 Weeks


✨ Features


✅ AES-256 encryption with CBC mode
✅ Password strength validation
✅ SHA-256 integrity hash after encryption and decryption
✅ Batch encryption & decryption of entire folders
✅ Custom output file naming
✅ Automatic encryption report logging
✅ Clean and simple CLI interface


🚀 How to Use


✅ Encrypt a Single File


bash
Copy
Edit
python encryptor.py encrypt mywallet.txt


✅ Encrypt with Custom Output Filename


bash
Copy
Edit
python encryptor.py encrypt mywallet.txt --output secure.dat.enc


✅ Decrypt a File


bash
Copy
Edit
python encryptor.py decrypt secure.dat.enc


✅ Batch Encrypt All Files in a Folder


bash
Copy
Edit
python encryptor.py encrypt-folder my_folder

✅ Batch Decrypt All .enc Files in a Folder

bash
Copy
Edit
python encryptor.py decrypt-folder my_folder


📦 Installation


Install required dependencies:

bash
Copy
Edit
pip install cryptography


🔍 How It Works


This tool uses the AES-256 encryption algorithm in CBC mode, a modern and secure method to protect data:

Key Derivation: Passwords are transformed into secure 256-bit keys via PBKDF2 + SHA-256 and 100,000 iterations.

Random IV: Each encryption generates a unique initialization vector.

Padding: Automatically pads files to match AES block size.

Integrity: After encryption/decryption, a SHA-256 hash validates file integrity.



🧠 Example Use Cases


Backing up blockchain wallets

Encrypting legal documents and certificates

Protecting confidential student or patient records

Safely archiving sensitive reports



⚙️ Command Reference


Command	Description
encrypt	Encrypt a single file
decrypt	Decrypt a single file
encrypt-folder	Encrypt all files in a folder
decrypt-folder	Decrypt all .enc files in a folder
--output	Specify a custom output filename


🛡️ Security Notes


Always choose strong, unique passwords.

Lost passwords cannot be recovered.

This tool does not store passwords or keys.

For educational purposes only.



🌐 Future Improvements


This project can be extended with:

GUI desktop interface

Cloud backup integration

File compression before encryption

Automated email notifications

GPG/PGP support
