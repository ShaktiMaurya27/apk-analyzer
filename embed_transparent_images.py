import base64

with open(r'd:\Github projects\apk-analyzer\assets\ladybug_transparent.png', 'rb') as f:
    ladybug_b64 = "data:image/png;base64," + base64.b64encode(f.read()).decode('utf-8')

with open(r'd:\Github projects\apk-analyzer\assets\bacteria_transparent.png', 'rb') as f:
    bacteria_b64 = "data:image/png;base64," + base64.b64encode(f.read()).decode('utf-8')

with open(r'd:\Github projects\apk-analyzer\index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Replace Ladybug SVG block with Transparent PNG
ladybug_png_html = f'''<!-- Animated Patrol Ladybug (Transparent PNG without Background) -->
      <div class="absolute top-2 left-4 z-30 pointer-events-auto ladybug-patrol cursor-pointer" title="Bug Hunter Patrol (Hover to pause)">
        <img src="{ladybug_b64}" alt="Ladybug Patrol" class="w-12 h-12 object-contain filter drop-shadow-[0_0_12px_rgba(239,68,68,0.7)]" />
      </div>'''

# Replace Bacteria SVG blocks with Transparent PNG
microbe1_html = f'''<!-- Cyber Microbe 1 (Top Right Corner Transparent PNG) -->
        <div class="absolute top-4 right-6 pointer-events-none microbe-float-1 opacity-80">
          <img src="{bacteria_b64}" alt="Microbe" class="w-16 h-16 object-contain filter drop-shadow-[0_0_12px_rgba(52,211,153,0.6)]" />
        </div>'''

microbe2_html = f'''<!-- Cyber Microbe 2 (Bottom Left Corner Transparent PNG) -->
        <div class="absolute bottom-4 left-8 pointer-events-none microbe-float-2 opacity-75">
          <img src="{bacteria_b64}" alt="Microbe" class="w-14 h-14 object-contain transform -rotate-45 filter drop-shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
        </div>'''

microbe3_html = f'''<!-- Cyber Microbe 3 (Bottom Right Corner Transparent PNG) -->
        <div class="absolute bottom-6 right-16 pointer-events-none microbe-float-3 opacity-60 hidden md:block">
          <img src="{bacteria_b64}" alt="Microbe" class="w-12 h-12 object-contain transform rotate-45 filter drop-shadow-[0_0_8px_rgba(110,231,183,0.4)]" />
        </div>'''

# Replace Ladybug block in HTML
import re
html = re.sub(
    r'<!-- Animated Patrol Ladybug \("Bug Hunter"\) -->\s*<div class="absolute top-2 left-4 z-30 pointer-events-auto ladybug-patrol cursor-pointer" title="Bug Hunter Patrol \(Hover to pause\)">[\s\S]*?</div>\s*</div>',
    ladybug_png_html,
    html,
    count=1
)

# Replace Microbe 1 block
html = re.sub(
    r'<!-- Cyber Microbe 1 \(Top Right Corner Vector Sticker\) -->\s*<div class="absolute top-4 right-6 pointer-events-none microbe-float-1 opacity-70">[\s\S]*?</div>\s*</div>',
    microbe1_html,
    html,
    count=1
)

# Replace Microbe 2 block
html = re.sub(
    r'<!-- Cyber Microbe 2 \(Bottom Left Corner Vector Sticker\) -->\s*<div class="absolute bottom-4 left-8 pointer-events-none microbe-float-2 opacity-65">[\s\S]*?</div>\s*</div>',
    microbe2_html,
    html,
    count=1
)

# Replace Microbe 3 block
html = re.sub(
    r'<!-- Cyber Microbe 3 \(Bottom Right Corner Vector Sticker\) -->\s*<div class="absolute bottom-6 right-16 pointer-events-none microbe-float-3 opacity-50 hidden md:block">[\s\S]*?</div>\s*</div>',
    microbe3_html,
    html,
    count=1
)

with open(r'd:\Github projects\apk-analyzer\index.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("[+] Successfully embedded transparent PNG images into index.html!")
