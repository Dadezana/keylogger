# Keylogger <br>![Linux](https://img.shields.io/badge/-linux-222?style=for-the-badge&logo=linux) ![MacOS](https://img.shields.io/badge/-macos-ffaa0f?style=for-the-badge&logo=apple) ![Windows](https://img.shields.io/badge/-windows-1ae?style=for-the-badge&logo=windows)<br>![Language](https://img.shields.io/badge/language-python-blue?style=for-the-badge&logo=python)

A keylogger written in python. <br>
Keys pressed are stored in a buffer and sent, encrypted, to the server.<br>
The server will store the data in a txt file named like the IP address of the victim

# How to run
### Install required libraries

```sh
pip install -r requirements.txt
```
In Arch Linux is suggested to install libraries via `pacman`, if possible
```sh
pacman -S python-rsa python-pycryptodome python-pynput
```
> `pynput` library is available in the [chaotic-aur](https://aur.chaotic.cx/) and [blackarch](https://www.blackarch.org/downloads.html#install-repo) repos

### Start the server
```sh
python server.py
```
### Start the client
```sh
python client.py
```
> If the client cannot connect to the server, it will retry to connect every 10 seconds


