from PIL import Image, ImageDraw, ImageFont
import colorsys
import os

print("Modifying verified_bg.webp...")
bg_img = Image.open('verified_bg.webp').convert("RGBA")
data = bg_img.getdata()
new_data = []
for r, g, b, a in data:
    if a == 0:
        new_data.append((0, 0, 0, 0))
        continue
    h, s, v = colorsys.rgb_to_hsv(r/255.0, g/255.0, b/255.0)
    v_boosted = min(v * 2.0, 1.0)
    dark = int(25 * v_boosted)
    new_data.append((dark, dark, dark, a))
bg_img.putdata(new_data)
bg_img.save('verified_bg.webp')

print("Modifying verified_fg.webp...")
fg_img = Image.new('RGBA', (128, 128), (0, 0, 0, 0))
draw = ImageDraw.Draw(fg_img)

font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
try:
    font = ImageFont.truetype(font_path, 42)
except:
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", 42)
    except:
        print("Could not find bold font, using default")
        font = ImageFont.load_default()

text = "FED"
bbox = draw.textbbox((0, 0), text, font=font)
w = bbox[2] - bbox[0]
h = bbox[3] - bbox[1]
x = (128 - w) / 2
y = (128 - h) / 2 - bbox[1]

border_color = (0, 0, 0, 255)
border_width = 3
for dx in range(-border_width, border_width+1):
    for dy in range(-border_width, border_width+1):
        if dx*dx + dy*dy <= border_width*border_width:
            draw.text((x+dx, y+dy), text, font=font, fill=border_color)

text_color = (183, 28, 28, 255) # Dark red
draw.text((x, y), text, font=font, fill=text_color)

fg_img.save('verified_fg.webp')
print("Done!")
