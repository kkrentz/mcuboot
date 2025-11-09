This fork of MCUboot features support for [TinyDICE](https://www.researchgate.net/publication/394424860_Streamlining_Security_Patches_and_Remote_Attestations_for_the_Internet_of_Things).

# Installation

After installing Zephyr like described [here](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) and activating the Python venv of Zephyr, take the following steps:

## Clone Zephyr fork

```bash
cd <zephyrproject>/zephyr
git add remote siemens git@code.siemens.com:sensorsystemintegration/funded-projects/ascot/tinydice/zephyr.git
git fetch --all
git checkout -b tinydice siemens/tinydice
west update
```

## Clone MCUboot fork

```bash
cd <zephyrproject>/bootloader/mcuboot
git add remote siemens git@code.siemens.com:sensorsystemintegration/funded-projects/ascot/tinydice/mcuboot.git
git fetch --all
git checkout -b tinydice siemens/tinydice
git submodule update --init --recursive
```

## Build tools

```bash
cd <path to zephyrproject>/bootloader/mcuboot/scripts
python3 setup.py install
cd <path to zephyrproject>/bootloader/mcuboot/scripts/dice
./build.sh
```

## Flash Layer 1

Connect a [B-U585I-IOT02A](https://www.st.com/en/evaluation-tools/b-u585i-iot02a.html) board via USB. Then:

```bash
cd <path to zephyrproject>/bootloader/mcuboot/samples/zephyr/dice
west build -b b_u585i_iot02a
west flash
```

## Flash root of trust

```bash
cd <path to zephyrproject>/bootloader/mcuboot/boot/zephyr
west build -b b_u585i_iot02a
west flash --no-erase
```

`--no-erase` retains other flash areas, such as the previously flashed Layer 1.

## Flash preliminary version of Layer 0

For issuing a Cert_L0 certificate, the certificate authority needs the public portion of the DeviceID. Our approach is to pass the public portion of the DeviceID to Layer 1, where we print it. This allows us to issue a Cert_L0, which we eventually attach to the Layer 0 image as an unprotected TLV. Unprotected TLVs are excluded from the hash computation by the root of trust, thereby preserving the certified DeviceID. In this manner, we avoid having debug outputs in Layer 0, which would increase to the trusted computing base.

In a separate console run

```bash
minicom -w -D /dev/ttyACM0
```

Modify [app.overlay](../boot/zephyr/app.overlay) like follows

```
/ {
	chosen {
		zephyr,code-partition = &mcuboot0_partition;
	};
};
```

and [prj.conf](../boot/zephyr/prj.conf) like follows

```
[...]
### Configure MCUboot either as DICE root of trust or DICE Layer 0
CONFIG_BOOT_DICE_ROT=y
CONFIG_BOOT_DICE_L0=n

# configure MCUboot as DICE Layer 0
CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS=""
[...]
```

```bash
west build -b b_u585i_iot02a
west flash --no-erase
```

Watch the serial output and find the public portion of the DeviceID.

Next, run:

```bash
cd <path to zephyrproject>/bootloader/mcuboot/scripts/dice
./build/tiny-dice-ca <private key> <subject> <TCI_L0> <DeviceID>
```

For example:

```
./build/tiny-dice-ca ../../root-ecqv-p256.b64 0xabcd 1 0266a4b7b5721538cc7c37a4ab55429badc9f425b7267288c41108f56f82a110e7
```

This produces the contents of the DICE TLV, which we now attach to the Layer 0 image.

## Flash final version of Layer 0

Now adapt [prj.conf](../boot/zephyr/prj.conf) like follows

```
[...]
### Configure MCUboot either as DICE root of trust or DICE Layer 0
CONFIG_BOOT_DICE_ROT=n
CONFIG_BOOT_DICE_L0=y

### Attach a DICE TLV to the Layer 0 image
CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS="--dice=<output of tiny-dice-ca>"
[...]
```

```bash
west build -b b_u585i_iot02a
west flash --no-erase
```

<details>

<summary>The output should now look like this:</summary>


```
I: Starting bootloader
D: context_boot_go
I: Primary image: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Scratch: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Boot source: primary slot
I: Image index: 0, Swap type: none
D: boot_validate_slot: slot 0, expected_swap_type 0
D: bootutil_img_validate: flash area 0x800a050
D: bootutil_img_hash
D: bootutil_tlv_iter_begin: type 65535, prot == 0
D: bootutil_img_validate: TLV off 56012, end 56240
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 56012 ending at 5
6240
D: bootutil_tlv_iter_next: TLV 16 found at 56016 (size 32)
D: bootutil_img_validate: EXPECTED_HASH_TLV == 16
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 56048 ending at 5
6240
D: bootutil_tlv_iter_next: TLV 1 found at 56052 (size 32)
D: bootutil_img_validate: EXPECTED_KEY_TLV == 1
D: bootutil_find_key
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 56084 ending at 5
6240
D: bootutil_tlv_iter_next: TLV 34 found at 56088 (size 71)
D: bootutil_img_validate: EXPECTED_SIG_TLV == 34
D: bootutil_verify_sig: ECDSA builtin key 0
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 56159 ending at 5
6240
D: bootutil_tlv_iter_next: TLV 38 found at 56163 (size 77)
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 56240 ending at 5
6240
D: bootutil_tlv_iter_next: TLV 65535 not found
D: bootutil_tlv_iter_begin: type 16, prot == 0
D: bootutil_tlv_iter_next: searching for 16 (65535 is any) starting at 56012 ending at 5624
0
D: bootutil_tlv_iter_next: TLV 16 found at 56016 (size 32)
D: Left boot_go with success == 1
I: Bootloader chainload address offset: 0x100000
I: Image version: v2.3.0
I: Jumping to the first image slot
I: Starting bootloader
D: context_boot_go
I: Primary image: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Scratch: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Boot source: primary slot
I: Image index: 0, Swap type: none
D: boot_validate_slot: slot 0, expected_swap_type 0
D: bootutil_img_validate: flash area 0x810c1a0
D: bootutil_img_hash
D: bootutil_tlv_iter_begin: type 65535, prot == 0
D: bootutil_img_validate: TLV off 32596, end 32744
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 32596 ending at 3
2744
D: bootutil_tlv_iter_next: TLV 16 found at 32600 (size 32)
D: bootutil_img_validate: EXPECTED_HASH_TLV == 16
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 32632 ending at 3
2744
D: bootutil_tlv_iter_next: TLV 1 found at 32636 (size 32)
D: bootutil_img_validate: EXPECTED_KEY_TLV == 1
D: bootutil_find_key
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 32668 ending at 3
2744
D: bootutil_tlv_iter_next: TLV 34 found at 32672 (size 72)
D: bootutil_img_validate: EXPECTED_SIG_TLV == 34
D: bootutil_verify_sig: ECDSA builtin key 0
D: bootutil_tlv_iter_next: searching for 65535 (65535 is any) starting at 32744 ending at 3
2744
D: bootutil_tlv_iter_next: TLV 65535 not found
D: bootutil_tlv_iter_begin: type 38, prot == 0
D: bootutil_tlv_iter_next: searching for 38 (65535 is any) starting at 56012 ending at 5624
0
D: bootutil_tlv_iter_next: TLV 38 found at 56163 (size 77)
D: Extracted Cert_L0 and s_L0 from DICE TLV
D: bootutil_tlv_iter_begin: type 16, prot == 0
D: bootutil_tlv_iter_next: searching for 16 (65535 is any) starting at 32596 ending at 3274
4
D: bootutil_tlv_iter_next: TLV 16 found at 32600 (size 32)
D: Cert_L1 has 111 bytes at rest
D: Left boot_go with success == 1
I: Bootloader chainload address offset: 0x10000
I: Image version: v0.0.0
I: Jumping to the first image slot
*** Booting Zephyr OS build v4.3.0-rc3-2-gcf6fd60e9c6a ***
Public (proto-)DeviceID: 0266a4b7b5721538cc7c37a4ab55429badc9f425b7267288c41108f56f82a110e7
Cert_L0: {
  subject: abcd,
  issuer: 1 (SHA-256),
  curve: 5 (secp256r1),
  reconstruction-data: 03ed2539c49805a6d129c1233144cc1782c21ff2fd0d70c06dc4f3b0ba3baff66c,
  tci: 1
}
Cert_L1: {
  subject: abcd,
  issuer: 47acb5fd0bf68091c80ba673ae5b106cc930edff2f817318e9964a79cd8a7c80,
  curve: 5 (secp256r1),
  reconstruction-data: 020fdc6a9c17994212fce661a45267c044f0e0f830e48dd60f2b3629aa5fba1f2c,
  tci: 517a7225d5213426de6bccabc8b6103a69e3f3e9b673f24adcf07fc20ada61ed
}
AKey_L0 (public): 02a49a6a1d3e59255d1776b2ce66d00a77e431f049692fdd94c7b3e7b9a5d591f6
AKey_L0 (private): 343ad73a1618862c5bc3a0a31f713ce0f9e572da21a0d56fc3bb784f1a27e8e1
CDI_L1: 5999fc055e2f8824d49714961a1b61ba07c99c10f804b4d6c46a1e4bf2f3b1db
Succeeded to reconstruct AKey_L0
```

</details>

# DICE without Cert_L0

If no Cert_L0 certificate is needed, one should still attach a DICE TLV in order to assign a name to the device like this:

```
CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS="--dice=<name as CBOR hex string> --protect-dice"
```

With a Python console, one can quickly generate such a CBOR hex string:

CBOR text string to hex string:

```
>>> from cbor2 import dumps
>>> dumps("foo").hex()
'63666f6f'
```

CBOR byte string to hex string:

```
>>> from cbor2 import dumps
>>> dumps(bytes.fromhex('abcd')).hex()
'42abcd'
```

Finally, these outputs have to be inserted in [prj.conf](../boot/zephyr/prj.conf) like so:

```
### Attach a DICE TLV to the Layer 0 image
CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS="--dice=0x42abcd --protect-dice"
```
