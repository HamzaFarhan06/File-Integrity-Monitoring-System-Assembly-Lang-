# FIM PRO – Assembly-Based File Integrity Monitor

## Overview

FIM PRO is an Assembly-Based File Integrity Monitoring system developed using x86 MASM Assembly and the Irvine32 library.

It monitors files and directories, detects unauthorized or unexpected modifications, and maintains a secure baseline using SHA-256 and HMAC-SHA-256.

## Features

- SHA-256 file hashing implemented in Assembly.
- HMAC-SHA-256 baseline protection.
- Recursive directory scanning.
- File modification detection.
- New and missing file detection.
- Real-time directory monitoring using Windows APIs.
- Timestamped event logging.
- Interactive console menu.

## Technologies Used

- x86 MASM Assembly
- Irvine32 Library
- Microsoft Visual Studio
- Windows API

## Requirements

1. Windows operating system.
2. Visual Studio with Desktop development with C++.
3. MASM assembler.
4. Irvine32 library.

## Setup Instructions

1. Clone or download this repository.
2. Install Visual Studio and the required C++ development tools.
3. Install the Irvine32 library.
4. Configure the Irvine32 include and library directories in Visual Studio.
5. Open the Visual Studio project.
6. Select the Win32/x86 platform.
7. Build the project.
8. Run the generated executable.

## Usage

1. Create a folder named `monitored` in the program's working directory.
2. Place the files you want to monitor inside it.
3. Run the program.
4. Initialize the baseline.
5. Run an integrity check or start real-time monitoring.
6. View the event history to inspect detected changes.

## Project Files

- `FIM_final.asm` – Main assembly source code.
- `task1.vcxproj` – Visual Studio project configuration.
- `task1.vcxproj.filters` – Solution Explorer organization.

## Author

Add your name here.

## Disclaimer

This project is developed for educational and demonstration purposes.
