# **Frida Patcher**

A lightweight cross‑platform tool for automatically injecting **Frida Gadget** into Android APKs.
iOS support is currently **under development**.


Alternatively, use objection :)

---

## **✨ Features**

* Auto-detect APK architecture (arm/arm64/x86/x86_64)
* Extract and patch `.so` files using **LIEF**
* Inject `libfrida-gadget.so` into selected library
* Supports **APKTool rebuild** or **ZIP-only fast patch**
* Automatic signing using Uber APK Signer
* Auto-download required tools:

  * APKTool
  * Uber APK Signer
  * Frida Gadget (all architectures)
  * Cross‑platform **7z** binary (macOS/Linux/Windows)

---

## **🍎 iOS Support (Under Development)**

* Detect IPA package
* Extract Payload and identify Mach‑O executable
  📌 Full injection + resigning workflow will be added in upcoming versions.

---

## **📦 Installation**

### **Requirements**

* Python 3.8+
* Java (for APKTool + signing)
* macOS / Linux / Windows

### **Install Python dependencies**

```bash
git clone https://github.com/vichhka-git/frida-patcher
```

*(LIEF and Frida Python module will auto-install if missing.)*

---

## **🚀 Example Usage**

### **Patch an APK**

```bash
python3 frida-patcher.py MyApp.apk
```

Example:

```bash
python3 frida-patcher.py MyApp.apk
adb install MyApp-patched.apk

#Open the app first then we can run frida hook
frida -U APP_NAME
```

---

## **📜 License**

This project is released under the **MIT License**.

---

## **🙌 Credits**

* **Frida Project** — [https://frida.re](https://frida.re)
* **APKTool** — [https://ibotpeaches.github.io/Apktool](https://ibotpeaches.github.io/Apktool)
* **Uber APK Signer**
* **LIEF Project** — [https://lief-project.github.io](https://lief-project.github.io)
