"""
generate_dataset.py
-------------------
Creates the 1,000 synthetic test files used by benchmark.py.

The files aren't random noise — they're modeled after real file types
(PE executables, shell scripts, ZIPs, PDFs, config files) so the YARA
rules have something meaningful to work against. Plain text files are
mixed in as a control group that shouldn't match anything.

The fixed random seed means anyone who clones the repo and runs this
will get the exact same 1,000 files, which is important for reproducibility.
"""

import os
import random
import string

OUTPUT_DIR = "dataset"
NUM_FILES  = 1000
SEED       = 42

random.seed(SEED)
os.makedirs(OUTPUT_DIR, exist_ok=True)


def random_bytes(n):
    return bytes(random.randint(0, 255) for _ in range(n))

def random_text(n_chars):
    # Printable ASCII with some whitespace mixed in, encoded to bytes
    chars = string.ascii_letters + string.digits + " \n\t.,;:!?-_/"
    return "".join(random.choice(chars) for _ in range(n_chars)).encode()


def make_pe_like():
    # Real PE files start with "MZ" and have "PE\x00\x00" a bit further in.
    # This is enough for the hex rule to match on the magic bytes.
    header = b"MZ" + random_bytes(58) + b"PE\x00\x00" + random_bytes(20)
    body   = random_bytes(random.randint(512, 4096))
    return header + body

def make_script_like():
    # Mix of shebangs so both python and bash variations show up in the dataset
    shebangs = [
        b"#!/usr/bin/python3\n",
        b"#!/bin/bash\n",
        b"#!/usr/bin/perl\n",
    ]
    lines = [
        b"import os\n",
        b"import socket\n",
        b"import sys\n",
        b"# auto-generated test script\n",
        b"def main():\n    pass\n",
        b"CreateRemoteThread = None\n",
    ]
    body = b"".join(random.choices(lines, k=random.randint(5, 20)))
    return random.choice(shebangs) + body + random_text(random.randint(200, 800))

def make_zip_like():
    # ZIP files always start with PK\x03\x04
    return b"PK\x03\x04" + random_bytes(random.randint(256, 2048))

def make_pdf_like():
    return b"%PDF-1.4\n" + random_text(random.randint(300, 1500))

def make_plain_text():
    # These shouldn't match any of the three rules — they're noise files
    # that let us see how many false positives each rule type produces.
    return random_text(random.randint(500, 3000))

def make_config_like():
    # Simulates a C2 beacon config — the kind of thing a threat hunter
    # would actually be looking for. Has a real-looking IP and callback URL
    # so the regex rule's IP and URL patterns have something to find.
    ip  = (f"{random.randint(1,254)}.{random.randint(0,254)}."
           f"{random.randint(0,254)}.{random.randint(1,254)}")
    url = f"https://example-c2-{random.randint(1000,9999)}.com/beacon"
    content = (
        f"[config]\nserver={ip}\nport={random.randint(1024,65535)}\n"
        f"callback_url={url}\ntimeout=30\n"
    )
    return content.encode() + random_text(random.randint(100, 400))


# Weighted so the dataset feels like a realistic file system sample.
# Heavy on plain text and PE files, lighter on ZIPs and PDFs.
GENERATORS = [
    (make_pe_like,     0.20),
    (make_script_like, 0.20),
    (make_zip_like,    0.10),
    (make_pdf_like,    0.10),
    (make_config_like, 0.15),
    (make_plain_text,  0.25),
]

funcs, weights = zip(*GENERATORS)

print(f"Generating {NUM_FILES} files in '{OUTPUT_DIR}/'...")

for i in range(NUM_FILES):
    gen      = random.choices(funcs, weights=weights, k=1)[0]
    data     = gen()
    filepath = os.path.join(OUTPUT_DIR, f"file_{i:04d}.bin")
    with open(filepath, "wb") as f:
        f.write(data)

    if (i + 1) % 100 == 0:
        print(f"  {i + 1}/{NUM_FILES}")

print(f"\nDone. {NUM_FILES} files written to '{OUTPUT_DIR}/'.")
print("Run benchmark.py next.")