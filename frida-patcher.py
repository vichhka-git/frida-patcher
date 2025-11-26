#!/usr/bin/env python3
import sys
import os
import argparse
import zipfile
import shutil
import subprocess
import urllib.request
from urllib.error import HTTPError, URLError
import stat
import json
import lzma
import gzip

# Known Mach-O / FAT magic numbers
MACHO_MAGICS = {
    0xfeedface,
    0xcefaedfe,
    0xfeedfacf,
    0xcffaedfe,
    0xcafebabe,
    0xbebafeca,
}

def _header_is_macho(header: bytes) -> bool:
    if len(header) < 4:
        return False
    val_be = int.from_bytes(header, "big")
    val_le = int.from_bytes(header, "little")
    return val_be in MACHO_MAGICS or val_le in MACHO_MAGICS

def run_cmd(cmd: list, cwd=None):
    print(f"[CMD] {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0:
        print(f"[!] Command failed: {' '.join(cmd)}")
        sys.exit(1)


def find_common_libs(lib_root: str):
    """
    Find .so filenames that exist across ALL valid ABI folders.
    Only ABIs inside FRIDA-supported list are considered.
    """
    VALID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}

    # Filter ABI folders
    abi_dirs = [abi for abi in os.listdir(lib_root)
                if abi in VALID_ABIS and
                os.path.isdir(os.path.join(lib_root, abi))]

    if not abi_dirs:
        print("[!] No valid ABI folders found (arm64-v8a, armeabi-v7a, x86, x86_64).")
        return []

    so_sets = []
    for abi in abi_dirs:
        path = os.path.join(lib_root, abi)
        so_files = {f for f in os.listdir(path) if f.endswith(".so")}
        if not so_files:
            print(f"[!] Warning: no .so files found in ABI {abi}")
        so_sets.append(so_files)

    # If any ABI folder had zero .so, skip it but don't break logic
    so_sets = [s for s in so_sets if len(s) > 0]

    if not so_sets:
        return []

    # intersection between all present valid ABI folders
    common = set.intersection(*so_sets)

    return sorted(list(common))



def detect_platform(path: str) -> str:
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as z:
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    if name.startswith("lib/") and name.endswith(".so"):
                        with z.open(name) as entry:
                            if entry.read(4).startswith(b"\x7fELF"):
                                return "android"

                    if name.startswith("Payload/") and ".app/" in name:
                        with z.open(name) as entry:
                            if _header_is_macho(entry.read(4)):
                                return "ios"

                # fallback scan
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    with z.open(name) as entry:
                        header = entry.read(4)
                        if header.startswith(b"\x7fELF"):
                            return "android"
                        if _header_is_macho(header):
                            return "ios"
        except Exception:
            return "unknown"

    # raw file
    try:
        with open(path, "rb") as f:
            header = f.read(4)
    except Exception:
        return "unknown"

    if header.startswith(b"\x7fELF"):
        return "android"
    if _header_is_macho(header):
        return "ios"

    return "unknown"

def download_file(url: str, dest: str) -> bool:
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except (HTTPError, URLError):
        return False

def make_executable(path: str) -> None:
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def extract_compressed(src: str, dest: str) -> None:
    """Extract .xz or .gz file to dest"""
    if src.endswith(".xz"):
        with lzma.open(src, "rb") as f_in:
            with open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    elif src.endswith(".gz"):
        with gzip.open(src, "rb") as f_in:
            with open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    else:
        shutil.copy(src, dest)

def ensure_tools() -> None:
    """Ensure required tools exist locally, including 7z binary."""
    tools_dir = os.path.join(os.path.dirname(__file__), "tools")
    os.makedirs(tools_dir, exist_ok=True)

    # -------------------------------
    # REQUIRE JAVA
    # -------------------------------
    if not shutil.which("java"):
        print("[!] Java runtime not detected on your system.")
        print("[!] APKTool and Uber APK Signer require Java to run.")
        print("")
        print("Please install Java manually first:")
        print("  Mac   :  brew install openjdk")
        print("  Linux :  sudo apt install default-jre   OR   sudo pacman -S jre-openjdk")
        print("  Win   :  https://adoptium.net   (Install Temurin JDK/JRE)")
        print("")
        sys.exit(1)

    # -------------------------------
    # APKTOOL
    # -------------------------------
    jar_dest = os.path.join(tools_dir, "apktool.jar")
    wrapper_dest = os.path.join(tools_dir, "apktool")
    if not os.path.exists(jar_dest):
        print("[*] Downloading latest APKTool jar...")
        try:
            with urllib.request.urlopen("https://api.github.com/repos/iBotPeaches/Apktool/releases/latest", timeout=15) as resp:
                data = json.load(resp)
            for a in data.get("assets", []):
                if a.get("name", "").endswith(".jar"):
                    url = a.get("browser_download_url")
                    if download_file(url, jar_dest):
                        print(f"[+] APKTool jar downloaded: {jar_dest}")
                        break
        except Exception as e:
            print(f"[!] Failed to download APKTool: {e}")

    if not os.path.exists(wrapper_dest) and os.path.exists(jar_dest):
        with open(wrapper_dest, "w") as w:
            w.write('#!/bin/sh\n')
            w.write(f'java -jar "{jar_dest}" "$@"\n')
        make_executable(wrapper_dest)
        print(f"[+] APKTool wrapper created: {wrapper_dest}")

    # -------------------------------
    # UBER-APK-SIGNER
    # -------------------------------
    uber_dest = os.path.join(tools_dir, "uber-apk-signer.jar")
    if not os.path.exists(uber_dest):
        url = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
        if download_file(url, uber_dest):
            print(f"[+] Uber APK Signer downloaded: {uber_dest}")

    # -------------------------------
    # LIEF
    # -------------------------------
    try:
        import lief
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "lief"], check=False)

    # -------------------------------
    # FRIDA detection & install
    # -------------------------------
    frida_version = None
    cli = shutil.which("frida")
    if cli:
        try:
            out = subprocess.check_output([cli, "--version"], text=True).strip()
            frida_version = out.lstrip("vV ")
            print(f"[+] Frida CLI detected: {frida_version}")
        except:
            frida_version = None

    if not frida_version:
        print("[!] Frida not detected — installing latest version...")
        system = sys.platform
        if system == "darwin":
            if shutil.which("brew"):
                os.system("brew install frida")
            else:
                print("[!] Homebrew missing — install from https://brew.sh/")
                sys.exit(1)
        elif system.startswith("linux"):
            os.system("pip3 install --upgrade frida-tools")
        else:
            print(f"[!] Unsupported OS: {system}")
            sys.exit(1)

        cli = shutil.which("frida")
        if cli:
            out = subprocess.check_output([cli, "--version"], text=True).strip()
            frida_version = out.lstrip("vV ")
            print(f"[+] Installed Frida version: {frida_version}")
        else:
            print("[!] Failed to install Frida.")
            sys.exit(1)

    try:
        import frida
        if not frida.__version__.startswith(frida_version):
            subprocess.run([sys.executable, "-m", "pip", "install", f"frida=={frida_version}"])
    except:
        subprocess.run([sys.executable, "-m", "pip", "install", f"frida=={frida_version}"])

    # -------------------------------
    # 7-ZIP DOWNLOAD
    # -------------------------------
    system = sys.platform
    arch = os.uname().machine if hasattr(os, "uname") else "x64"
    sevenz_bin = os.path.join(tools_dir, "7z")

    if system == "darwin":
        url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-mac.tar.xz"
        dest = os.path.join(tools_dir, "7z.tar.xz")
    elif system.startswith("linux"):
        if arch in ("aarch64", "arm64"):
            url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-linux-arm64.tar.xz"
        elif arch.startswith("arm"):
            url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-linux-arm.tar.xz"
        elif arch in ("x86_64", "amd64"):
            url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-linux-x64.tar.xz"
        else:
            url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-linux-x86.tar.xz"
        dest = os.path.join(tools_dir, "7z.tar.xz")
    elif system in ("win32", "cygwin"):
        url = "https://github.com/ip7z/7zip/releases/download/25.01/7z2501-arm.exe"
        dest = os.path.join(tools_dir, "7z.exe")
        sevenz_bin = dest
    else:
        print(f"[!] Unsupported OS for 7z: {system}")
        sys.exit(1)

    # Download and extract 7z if not exists
    if not os.path.exists(sevenz_bin):
        print(f"[*] Downloading 7z from {url} ...")
        if not download_file(url, dest):
            print("[!] Failed to download 7z binary.")
            sys.exit(1)

        if dest.endswith(".tar.xz"):
            import tarfile
            with tarfile.open(dest, "r:xz") as tar:
                # Extract only the 7zz binary
                member_name = next((m.name for m in tar.getmembers() if m.name.endswith("7zz")), None)
                if not member_name:
                    print("[!] 7zz binary not found inside archive")
                    sys.exit(1)
                tar.extract(member_name, tools_dir)
                extracted_path = os.path.join(tools_dir, member_name)
                shutil.move(extracted_path, sevenz_bin)
            os.remove(dest)
            make_executable(sevenz_bin)
        elif dest.endswith(".exe"):
            # Windows: already executable
            pass
        print(f"[+] 7z ready at {sevenz_bin}")

    # -------------------------------
    # FRIDA GADGETS
    # -------------------------------
    gadgets_dir = os.path.join(tools_dir, "frida-gadgets")
    os.makedirs(gadgets_dir, exist_ok=True)

    android_arches = ["android-arm", "android-arm64", "android-x86", "android-x86_64"]
    ios_arches = ["ios-universal", "ios-simulator-universal"]

    for arch in android_arches + ios_arches:
        ext = ".so.xz" if "android" in arch else ".dylib.xz"
        filename = f"frida-gadget-{frida_version}-{arch}{ext}"
        url = f"https://github.com/frida/frida/releases/download/{frida_version}/{filename}"
        dest = os.path.join(gadgets_dir, filename)
        final_file = dest.replace(".xz", "").replace(".gz", "")
        if os.path.exists(final_file):
            continue

        print(f"[*] Downloading {filename} ...")
        ok = download_file(url, dest)
        if not ok and "ios" in arch:
            alt = filename.replace(".xz", ".gz")
            url = f"https://github.com/frida/frida/releases/download/{frida_version}/{alt}"
            dest_alt = dest.replace(".xz", ".gz")
            print(f"[*] Retrying with {alt} ...")
            ok = download_file(url, dest_alt)
            if ok:
                dest = dest_alt
                filename = alt
        if not ok:
            print(f"[!] Failed to download {filename}")
            continue

        print(f"[*] Extracting {filename} ...")
        extract_compressed(dest, final_file)
        try:
            os.remove(dest)
            print(f"[*] Removed compressed file: {dest}")
        except:
            pass
        make_executable(final_file)
        print(f"[+] Ready: {final_file}")

def patch_android_gadget_apktool(apk_path: str, tools_dir: str, frida_version: str):
    import lief
    import xml.etree.ElementTree as ET

    print("[*] Starting Android Gadget Patching...")

    apktool_jar = os.path.join(tools_dir, "apktool.jar")
    uber = os.path.join(tools_dir, "uber-apk-signer.jar")
    gadgets_dir = os.path.join(tools_dir, "frida-gadgets")

    temp_dir = "temp_apk"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    # ----------------------------------------------------
    # 1) Decompile APK
    # ----------------------------------------------------
    print("[*] Decompiling APK...")
    run_cmd(["java", "-jar", apktool_jar, "empty-framework-dir"])
    run_cmd(["java", "-jar", apktool_jar, "d", "-s", apk_path, "-o", temp_dir, "-f"])

    lib_root = os.path.join(temp_dir, "lib")
    if not os.path.exists(lib_root):
        print("[!] APK has no lib/ folder. Cannot patch.")
        sys.exit(1)

    VALID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}

    # ----------------------------------------------------
    # 2) Find SO libs present in all ABI folders
    # ----------------------------------------------------
    print("[*] Scanning ABI folders for native libraries...")
    candidates = find_common_libs(lib_root)

    if not candidates:
        print("[!] No common shared libraries across architectures.")
        sys.exit(1)

    print("\n[+] Libraries detected in ALL supported architectures:")
    for i, so in enumerate(candidates, 1):
        print(f"  {i}. {so}")

    choice = input("\nSelect library to patch by number: ").strip()
    try:
        target_so = candidates[int(choice) - 1]
    except:
        print("[!] Invalid selection.")
        sys.exit(1)

    print(f"[+] Selected for patching: {target_so}\n")

    # ABI → gadget map
    gadget_map = {
        "arm64-v8a": f"frida-gadget-{frida_version}-android-arm64.so",
        "armeabi-v7a": f"frida-gadget-{frida_version}-android-arm.so",
        "x86": f"frida-gadget-{frida_version}-android-x86.so",
        "x86_64": f"frida-gadget-{frida_version}-android-x86_64.so",
    }

    # ----------------------------------------------------
    # 3) Patch library + add gadget for each ABI
    # ----------------------------------------------------
    abi_folders = [d for d in os.listdir(lib_root) if d in VALID_ABIS]

    if not abi_folders:
        print("[!] No supported ABI folders found.")
        sys.exit(1)

    for abi in abi_folders:
        abi_path = os.path.join(lib_root, abi)
        so_path = os.path.join(abi_path, target_so)

        if not os.path.exists(so_path):
            print(f"[!] Skipping {abi} (missing {target_so})")
            continue

        print(f"[*] Patching {so_path} ...")
        original = lief.parse(so_path)
        original.add_library("libfrida-gadget.so")
        original.write(so_path)
        print(f"[+] Patched ABI: {abi}")

        # Copy matching gadget
        gadget_file = gadget_map.get(abi)
        if gadget_file:
            gadget_src = os.path.join(gadgets_dir, gadget_file)
            gadget_dst = os.path.join(abi_path, "libfrida-gadget.so")
            shutil.copy(gadget_src, gadget_dst)
            print(f"[+] Added gadget: {gadget_dst}")
        else:
            print(f"[!] No gadget found for ABI {abi}")

    # ----------------------------------------------------
    # 3.5) MODIFY MANIFEST (Enable debug, Internet, external libs)
    # ----------------------------------------------------
    print("[*] Modifying AndroidManifest.xml ...")

    manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
    ET.register_namespace('android', "http://schemas.android.com/apk/res/android")
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    # 1. Add uses-permission INTERNET
    def ensure_permission(name):
        for perm in root.findall("uses-permission"):
            if perm.get(ANDROID_NS + "name") == name:
                return
        p = ET.Element("uses-permission")
        p.set(ANDROID_NS + "name", name)
        root.insert(0, p)

    ensure_permission("android.permission.INTERNET")
    ensure_permission("android.permission.ACCESS_NETWORK_STATE")
    ensure_permission("android.permission.WRITE_EXTERNAL_STORAGE")
    ensure_permission("android.permission.READ_EXTERNAL_STORAGE")

    # 2. Force debuggable="true"
    app_node = root.find("application")
    if app_node is not None:
        print("[+] Setting application android:debuggable=true")
        app_node.set(ANDROID_NS + "debuggable", "true")

        print("[+] Setting application android:extractNativeLibs=true")
        app_node.set(ANDROID_NS + "extractNativeLibs", "true")

    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    print("[+] Manifest updated successfully!")

    # ----------------------------------------------------
    # 4) Rebuild APK
    # ----------------------------------------------------
    print("\n[*] Rebuilding patched APK...")
    out_apk = "patched-unsigned.apk"
    run_cmd(["java", "-jar", apktool_jar, "b", temp_dir, "-o", out_apk])

    # ----------------------------------------------------
    # 5) Sign APK
    # ----------------------------------------------------
    print("[*] Signing APK...")

    signed_out_dir = "signed_output"
    if os.path.exists(signed_out_dir):
        shutil.rmtree(signed_out_dir)
    os.makedirs(signed_out_dir)

    run_cmd([
        "java", "-jar", uber,
        "-a", out_apk,
        "-o", signed_out_dir
    ])

    # Find signed output
    signed = None
    for f in os.listdir(signed_out_dir):
        if f.endswith(".apk"):
            signed = os.path.join(signed_out_dir, f)
            break

    if not signed:
        print("[!] Signing failed — no APK generated.")
        sys.exit(1)

    final_apk = apk_path.replace(".apk", "-patched.apk")
    shutil.move(signed, final_apk)
    print(f"[✓] Final patched APK saved as: {final_apk}")

    # ----------------------------------------------------
    # 6) CLEANUP
    # ----------------------------------------------------
    print("\n[*] Cleaning up temporary files...")

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[+] Deleted {temp_dir}")

    if os.path.exists(out_apk):
        os.remove(out_apk)
        print(f"[+] Deleted {out_apk}")

    if os.path.exists(signed_out_dir):
        shutil.rmtree(signed_out_dir)
        print(f"[+] Deleted {signed_out_dir}")

    print("[✓] Cleanup complete.")
    print("[✓] Android gadget injection completed successfully!\n")


def patch_android_gadget_zip(apk_path: str, tools_dir: str, frida_version: str):
    import lief
    import zipfile

    print("[*] Starting Android Gadget Patching...")

    uber = os.path.join(tools_dir, "uber-apk-signer.jar")
    gadgets_dir = os.path.join(tools_dir, "frida-gadgets")
    project_root = os.path.dirname(os.path.abspath(apk_path))

    # Extract only lib dir
    extract_lib = os.path.join(os.path.dirname(os.path.abspath(apk_path)), "lib_extract")
    if os.path.exists(extract_lib):
        shutil.rmtree(extract_lib)
    os.makedirs(extract_lib)

    # ----------------------------------------------------
    # 1) Extract ONLY /lib/ from APK
    # ----------------------------------------------------
    print("[*] Extracting /lib from APK...")

    with zipfile.ZipFile(apk_path, "r") as z:
        for item in z.infolist():
            if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                z.extract(item, extract_lib)

    lib_root = os.path.join(extract_lib, "lib")

    VALID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}

    # ----------------------------------------------------
    # 2) Find common libs across ABIs
    # ----------------------------------------------------
    print("[*] Searching for common .so libs...")

    candidates = find_common_libs(lib_root)
    if not candidates:
        print("[!] No matching .so files found in all ABIs.")
        sys.exit(1)

    print("\n[+] Common libs:")
    for i, so in enumerate(candidates, 1):
        print(f"  {i}. {so}")

    choice = input("\nSelect library to patch: ").strip()
    target_so = candidates[int(choice) - 1]

    print(f"[+] Selected → {target_so}")

    gadget_map = {
        "arm64-v8a": f"frida-gadget-{frida_version}-android-arm64.so",
        "armeabi-v7a": f"frida-gadget-{frida_version}-android-arm.so",
        "x86": f"frida-gadget-{frida_version}-android-x86.so",
        "x86_64": f"frida-gadget-{frida_version}-android-x86_64.so",
    }

    # ----------------------------------------------------
    # 3) Patch with LIEF + copy gadgets
    # ----------------------------------------------------
    for abi in os.listdir(lib_root):
        abi_path = os.path.join(lib_root, abi)
        so_path = os.path.join(abi_path, target_so)

        if not os.path.exists(so_path):
            continue

        print(f"[*] Patching → {so_path}")
        lib = lief.parse(so_path)
        lib.add_library("libfrida-gadget.so")
        lib.write(so_path)

        gadget_src = os.path.join(gadgets_dir, gadget_map[abi])
        shutil.copy(gadget_src, os.path.join(abi_path, "libfrida-gadget.so"))

        print(f"[+] Injected gadget into {abi}")

    # ----------------------------------------------------
    # 4) Repack APK using ONLY lib folder (7z overwrite)
    # ----------------------------------------------------
    print("[*] Replacing lib/ folder inside APK using 7z...")

    seven_zip = os.path.abspath(os.path.join(tools_dir, "7z"))
    unsigned_apk = os.path.abspath(apk_path.replace(".apk", "-patched-unsigned.apk"))
    lib_absolute = os.path.abspath(os.path.join(extract_lib, "lib"))

    # Make a copy of original APK
    shutil.copy(apk_path, unsigned_apk)

    cmd = [
        seven_zip,
        "a",
        "-tzip",
        "-mtp=0",
        "-mm=Deflate",
        "-mmt=on",
        "-mx3",
        "-mfb=32",
        "-mpass=1",
        "-sccUTF-8",
        "-mcu=on",
        "-mem=AES256",
        "-bb0",
        "-bse0",
        "-snl",
        "-mtc=on",
        "-mta=on",
        unsigned_apk,
        lib_absolute
    ]

    print("[*] Executing:", " ".join(cmd))
    run_cmd(cmd)


    # ----------------------------------------------------
    # 5) Sign APK
    # ----------------------------------------------------
    print("[*] Signing...")
    signed_dir = os.path.join(project_root, "signed_output")
    if os.path.exists(signed_dir):
        shutil.rmtree(signed_dir)
    os.makedirs(signed_dir)

    run_cmd(["java", "-jar", uber, "-a", unsigned_apk, "-o", signed_dir])

    final_apk = None
    for f in os.listdir(signed_dir):
        if f.endswith(".apk"):
            final_apk = apk_path.replace(".apk", "-patched.apk")
            shutil.move(os.path.join(signed_dir, f), final_apk)
            break

    if not final_apk:
        print("[!] Signing failed — no APK generated.")
        sys.exit(1)

    # ----------------------------------------------------
    # 6) Cleanup
    # ----------------------------------------------------
    shutil.rmtree(os.path.join(project_root, extract_lib))
    shutil.rmtree(signed_dir)
    os.remove(unsigned_apk)

    print(f"\n[✓] DONE → {final_apk}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: file not found: {args.file}")
        sys.exit(2)

    ensure_tools()

    # Detect platform
    platform = detect_platform(args.file)

    print(f"[+] Detected platform: {platform}")

    tools_dir = os.path.join(os.path.dirname(__file__), "tools")

    # Read installed Frida version for gadget mapping
    try:
        out = subprocess.check_output(["frida", "--version"], text=True).strip()
        frida_version = out.lstrip("vV ")
    except Exception:
        frida_version = None

    # ---------------------------
    # ANDROID PATCHING
    # ---------------------------
    if platform == "android":
        print("[*] Android platform detected → starting gadget patch...")
        patch_android_gadget_zip(args.file, tools_dir, frida_version)
        sys.exit(0)

    # ---------------------------
    # iOS PLACEHOLDER
    # ---------------------------
    elif platform == "ios":
        print("[!] iOS gadget patching is under development…")
        print("[!] For now only Android is supported.")
        sys.exit(0)

    # ---------------------------
    # UNKNOWN
    # ---------------------------
    else:
        print("[!] Unknown platform. Cannot continue.")
        sys.exit(1)

if __name__ == "__main__":
    main()
