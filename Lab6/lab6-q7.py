from pathlib import Path
from PIL import Image, ExifTags
import base64
import csv
import re

image_dir = Path("Images")
results = []

for image_path in sorted(image_dir.glob("*.png")):
    with Image.open(image_path) as img:
        metadata = {}

        # 1. EXIF metadata
        for tag_id, value in img.getexif().items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            metadata[f"EXIF:{tag}"] = str(value)

        # 2. PNG text and other metadata
        for key, value in img.info.items():
            if key.lower() in ("xmp", "xml:com.adobe.xmp"):
                field = f"XMP:{key}"
            else:
                field = f"PNG:{key}"

            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")

            metadata[field] = str(value)

    suspected = []
    encodings = []
    reasons = []
    score = 0

    # 3. Inspect metadata values
    for field, value in metadata.items():
        # Look for labelled messages, without assuming their content
        if re.search(r"\b[A-Z][A-Z0-9_]*:", value):
            suspected.append(field)

        # Check whether the value may be Base64
        compact = "".join(value.split())

        if len(compact) >= 16:
            try:
                decoded = base64.b64decode(
                    compact, validate=True
                ).decode("utf-8")

                if decoded.isprintable():
                    encodings.append(field)

            except (ValueError, UnicodeDecodeError):
                pass

    # 4. Apply simple heuristic scoring
    if suspected:
        score += 10
        reasons.append("+10: Labelled message found in metadata")

    if encodings:
        score += 5
        reasons.append("+5: Readable Base64 candidate found")

    # Additional unusual metadata needs manual review.
    # Do not add another 5 just for the same encoded value.

    results.append({
        "filename": image_path.name,
        "format": img.format,
        "metadata_fields": ", ".join(metadata.keys()),
        "suspected_field": ", ".join(suspected),
        "encoding": (
            "Possible Base64: " + ", ".join(encodings)
            if encodings else "None identified"
        ),
        "risk_score": score,
        "reason": "; ".join(reasons) if reasons else
                  "No indicators matched; manual review may still be needed."
    })

# 5. Export CSV
fields = [
    "filename", "format", "metadata_fields",
    "suspected_field", "encoding", "risk_score", "reason"
]

with open("metadata_report.csv", "w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(results)

print(f"Saved {len(results)} images to metadata_report.csv")
