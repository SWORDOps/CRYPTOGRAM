import re
import os

filepath = 'theme_unzipped/colors.tdesktop-theme'

with open(filepath, 'r') as f:
    content = f.read()

replacements = {
    'windowBg': '#050505',
    'windowBgOver': '#121212',
    'windowBgActive': '#700000',
    'activeButtonBg': '#700000',
    'activeButtonBgOver': '#500000',
    'activeButtonBgRipple': '#500000',
    'lightButtonBg': '#151515',
    'lightButtonBgOver': '#202020',
    'dialogsBg': '#050505',
    'dialogsBgOver': '#121212',
    'dialogsBgActive': '#700000',
    'boxBg': '#050505',
    'titleBg': '#050505',
    'titleBgActive': '#050505',
    'topBarBg': '#050505',
    'msgInBg': '#151515',
    'msgInBgSelected': '#252525',
    'msgOutBg': '#700000',
    'msgOutBgSelected': '#500000',
    'historyTextInFg': '#ffffff',
    'historyTextOutFg': '#ffffff',
    'menuBg': '#050505',
    'menuBgOver': '#121212',
}

for key, val in replacements.items():
    # Replace lines that start with the key (with optional spaces) followed by colon
    pattern = r'^(\s*' + key + r'\s*:\s*)[^;]+(.*)$'
    content = re.sub(pattern, r'\g<1>' + val + r'\g<2>', content, flags=re.MULTILINE)

with open(filepath, 'w') as f:
    f.write(content)

print("Theme patched successfully!")
