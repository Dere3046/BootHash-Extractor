# BootHash-Extractor

## Project Introduction
This Android application extracts and verifies the device's Verified Boot Hash through key attestation, providing a way to check device integrity and secure boot status.

## Features
- Generates key pairs using Android Keystore system
- Extracts Verified Boot Hash from attestation certificates
- Saves hash values to public directory for external access
- Smart file management: only updates when values change

## File Locations

### Primary File (Public Directory)
```

/storage/emulated/0/Download/KeyAttestation/verified_boot_hash.txt

```

### Backup File (App Private Directory)
```

/data/data/com.dere.keyattestation/files/verified_boot_hash.txt

```

## File Content

### Success Case
Hexadecimal string of Verified Boot Hash

### Failure Case
```

VERIFIED_BOOT_HASH_NOT_FOUND

```

## Requirements
- Android 7.0+ (API level 24)
- External storage permissions
- Hardware-backed keystore support

## Acknowledgments
Inspired by the [KeyAttestation](https://github.com/vvb2060/KeyAttestation) repository implementation.