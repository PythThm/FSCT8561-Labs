from pathlib import Path
from PIL import Image, ExifTags
import base64

image_dir = Path("Images")
print("Images found:", len(list(image_dir.glob("*.png"))))

images = [file.name for file in image_dir.iterdir()
          if file.suffix.lower() == ".png"]

# 1
# for image in images:
#     image_path = image_dir / image
#     with Image.open(image_path) as img:
#         exif = img.getexif()
#         print("EXIF tags:", len(exif))
#         print(image_path)
#         for tag_id, value in exif.items():
#             print(ExifTags.TAGS.get(tag_id, tag_id), ":", value)

# 2
# for image in images:
#     image_path = image_dir / image
#     with Image.open(image_path) as img:
#         print(image_path)
#         for key, value in img.info.items():
#             if isinstance(value, str):
#                 print(key, ":", value)

# 3
# image_path = image_dir / "Dopamine.png"
# with Image.open(image_path) as img:
#     xmp = img.info.get("XML:com.adobe.xmp") or img.info.get("xmp")
#     if isinstance(xmp, bytes):
#         xmp = xmp.decode("utf-8", errors="replace")
#     print(xmp if xmp else "No XMP found")

# 4

encoded_message = "RVhGSUw6IFR1bm5lbCBjb21wcmVzc2VkIGRhdGFiYXNlIGR1bXAgdmlhIEROUyBDb3ZlcnQgQ2hhbm5lbC4="  
if encoded_message:
    print(base64.b64decode(encoded_message).decode("utf-8"))