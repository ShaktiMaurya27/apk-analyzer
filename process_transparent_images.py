import os
from PIL import Image

def remove_white_bg(input_path, output_path, threshold=225):
    img = Image.open(input_path).convert("RGBA")
    datas = img.getdata()

    new_data = []
    for item in datas:
        # Check if pixel is close to white
        r, g, b, a = item
        if r > threshold and g > threshold and b > threshold:
            # Make white/near-white pixel transparent
            new_data.append((255, 255, 255, 0))
        else:
            new_data.append((r, g, b, a))

    img.putdata(new_data)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path, "PNG")
    print(f"[+] Processed and saved transparent PNG to: {output_path}")

img1 = r"C:\Users\Shivansh\.gemini\antigravity\brain\d275a895-201d-4209-b9b4-650d04c2e5b1\.user_uploaded\media_1791213828282.png"
img2 = r"C:\Users\Shivansh\.gemini\antigravity\brain\d275a895-201d-4209-b9b4-650d04c2e5b1\.user_uploaded\media_1791213828285.png"

out1 = r"d:\Github projects\apk-analyzer\assets\ladybug_transparent.png"
out2 = r"d:\Github projects\apk-analyzer\assets\bacteria_transparent.png"

remove_white_bg(img1, out1)
remove_white_bg(img2, out2)
