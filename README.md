# Encrypt & Decrypt App

## Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install Dependencies](#install-dependencies)
  - [Install Dependencies](#install-dependencies)
- [Usage](#usage)
  - [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [Graphical User Interface (GUI)](#graphical-user-interface-gui)
- [Encryption Key Management](#encryption-key-management)

## Overview

- Encrypt & Decrypt App is a Python application designed to provide file encryption and decryption functionality through both a graphical user interface (GUI) and a command-line interface (CLI). The application allows users to securely encrypt and decrypt single or multiple files using industry-standard encryption methods. It is implemented using the PyQt5 library for the GUI and supports both GUI and CLI modes.

## Features

- **File Encryption**: Securely encrypt single or multiple files.
- **File Decryption**: Securely decrypt single or multiple files.
- **File Archive**: Export and Import As Archive formats.
- **Dual Interface**: Choose between a graphical user interface (GUI) and a command-line interface (CLI).
- **Cross-Platform**: Works on Windows, macOS, and Linux.
- **Simple & Intuitive UI**: User-friendly interface designed with PyQt5.
- **Secure**: Utilizes the `cryptography` library for strong encryption.

## Project Structure

```bash
encrypt_decrypt_app/
│
├── app/
│ ├── init.py
│ ├── main.py # Entry point for the application
│ ├── controller.py # Handles the interaction between the model and view
│ ├── model.py # Business logic for encryption and decryption
│ ├── view.py # CLI interaction logic
│ ├── cli.py # Command-line interface implementation
│
├── gui/
│ ├── init.py
│ ├── main_window.py # Main GUI window
│ ├── file_selection.py # File selection dialog
│
├── resources/
│ ├── icon.png # Application icon (if any)
│
├── README.md # This file
├── setup.py # Setup script for packaging
└── requirements.txt # Python dependencies
```

## Installation

### Prerequisites

- **Python 3.12**
- **pip** (Python Package Manager)

### Clone the Repository

```bash
git clone https://github.com/LahiruDilhara/lktd-enc.git
cd lktd-enc
```

### Install Dependencies

- You can install the required Python packages using pip

```bash
pip install -r requirements.txt
```

- Alternatively, you can install the package locally

```bash
pip install .
```

## Usage

### Command-Line Interface (CLI)

- To use the CLI, navigate to the project directory and run

```bash
python -m app.main -e/-d --output [output_dir] --password [password] [file1 file2 ...]
```

- --output: Directory to save the processed files.
- --key: Encryption/Decryption key.
- -e/-d: Choose between encryption or decryption.
- --password: Set the password

### Graphical User Interface (GUI)

- To launch the GUI, simply run

```bash
python -m app.main --gui
```

- The GUI allows you to select files, specify the output directory, and provide the encryption/decryption key through a user-friendly interface.

## Example Usage

### Encrypt Files via CLI

```bash
python -m app.main --encrypt  --output /path/to/output --password s8cr8tkey example.txt
```

```bash
python -m app.main --encrypt --output /path/to/output --zip --password s8cr8tkey  example.txt 
```

### Decrypt Files via CLI

```bash
python -m app.main --decrypt --output /path/to/output --password s8cr8tkey example.txt.encrypted 
```

```bash
python -m app.main --decrypt  --zip --output /path/to/output --password s8cr8tkey example.zip
```

### Launch GUI

```bash
python -m app.main --gui
```

## Encryption Key Management

- The application uses the cryptography library for encryption, which requires a 32-byte key. You can generate a key using the following Python snippet

```py
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())  # Store this key securely
```

## Contribution

- Contributions are welcome! If you'd like to contribute, please fork the repository, make your changes, and submit a pull request.

## License

- This project is licensed under the MIT License. See the LICENSE file for more details.

## Contact

- For any questions, suggestions, or issues, please feel free to reach out to Lahiru Dilhara.

## Summary of the Sections:

1. **Overview**: A brief description of the project and its purpose.
2. **Features**: Highlights the key features of the application.
3. **Project Structure**: Describes the directory structure and important files in the project.
4. **Installation**: Provides steps to clone the repository, install dependencies, and set up the project.
5. **Usage**: Explains how to use both the CLI and GUI, including example commands.
6. **Encryption Key Management**: Guides users on generating and managing encryption keys.
7. **Contributing**: Encourages contributions and explains how to contribute.
8. **License**: Specifies the project's license.
9. **Contact**: Provides contact information for support or questions.