# Mjölnir

Built in **Rust** and **C++**, **Mjölnir** is a powerful anti-cheat system designed with robust memory monitoring and lightning-fast detection to instantly crush unauthorized injections. Engineered to protect server environments with Nordic strength and precision, when the hammer falls, it’s game over for cheaters.


## Architecture & Tech Stack

Mjölnir combines the raw performance and low-level hardware control of C++ with the modern, memory-safe orchestration of Rust.

* **C++ Core:** Handles low-level memory auditing, process handle protection, API hook detection, and performance-critical validation checks.
* **Rust Backend:** Manages asynchronous telemetry streaming, configuration parsing, safe Inter-Process Communication (IPC), and core daemon orchestration without garbage collection stutter.


##  Core Features & Capabilities

* **Memory Integrity Monitoring:** Scans for unbacked executable memory regions, unapproved page modifications, and suspicious thread creations (`CreateRemoteThread`).
* **Injection Defense:** Neutralizes standard and manual-mapped DLL injections, handle stripping attempts, and malicious API hooking.
* **Hardware-Level Awareness:** Audits and enforces platform security configurations (such as IOMMU/VT-d settings) to mitigate low-level hardware threats.
* **Lightning-Fast Daemon:** Built as a lightweight, resource-efficient command-line service with minimal overhead on the host system.

## System Requirements

* **Operating System:** Windows 10 / 11 (x64) / linux (x64)
* **Build Tools:** 
  * MSVC (Visual Studio C++ build tools)
  * Rust (`rustup` with stable toolchain)
  * CMake (for C++ components)

---

## Getting Started

### 1. Cloning the Repository
```bash
git clone [https://github.com/your-username/mjolnir.git](https://github.com/your-username/mjolnir.git)
cd mjolnir
