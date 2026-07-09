import os
import glob
from PIL import Image
import colorsys

def recolor_image(path):
    try:
        img = Image.open(path).convert("RGBA")
        data = img.getdata()
        new_data = []
        for r, g, b, a in data:
            if a == 0:
                new_data.append((0, 0, 0, 0))
                continue
            h, s, v = colorsys.rgb_to_hsv(r/255.0, g/255.0, b/255.0)
            blend = min(max((s - 0.15) / 0.25, 0.0), 1.0)
            red_r, red_g, red_b = 229 * v, 57 * v, 53 * v
            v_boosted = min(v * 1.5, 1.0)
            blk_r, blk_g, blk_b = 17 * v_boosted, 17 * v_boosted, 17 * v_boosted
            out_r = red_r * (1 - blend) + blk_r * blend
            out_g = red_g * (1 - blend) + blk_g * blend
            out_b = red_b * (1 - blend) + blk_b * blend
            new_data.append((int(out_r), int(out_g), int(out_b), a))
        img.putdata(new_data)
        # Handle ICO format properly
        if path.endswith('.ico'):
            img.save(path, format='ICO', sizes=[(256, 256)])
        else:
            img.save(path)
        print(f"Successfully themed {path}")
    except Exception as e:
        print(f"Skipping {path}: {e}")

if __name__ == '__main__':
    for f in glob.glob("*.png") + glob.glob("*.ico"):
        recolor_image(f)
