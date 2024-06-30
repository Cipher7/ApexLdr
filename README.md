# ApexLdr

## Features

- DLL sideloading
- Shellcode staging via HTTP/S
- CRT Library Independent
- Indirect syscalls with Syswhispers3 - jumper_randomized
- Payload execution via Threadpool API
- DLL unhooking
- Import Address Table Camoflage
- API Hashing

## Usage

## Testing with Havoc and Windows Defender

## Note
> **Shellcode Encryption :** The shellcode is being fetched from a remote server, providing SSL Support. I haven't incorporated any shellcode encryption and decryption procedures to keep the loader simple and maintain a low entropy.
>
> **EDR Evasion? :** This is my first DLL Payload Loader, it can easily bypass many AV solutions and EDRs but some of the techniques it incorporates aren't the best, so as I keep learning I'll make better loaders!