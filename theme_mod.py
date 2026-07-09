import os

def hex_to_int(hex_str):
    # hex_str is something like '#700000'
    val = int(hex_str.replace('#', ''), 16)
    # Convert to 32-bit signed integer for Android (AARRGGBB)
    val = val | 0xFF000000
    if val > 0x7FFFFFFF:
        val -= 0x100000000
    return val

COLOR_MAPPINGS = {
    'windowBackgroundWhite': '#050505',
    'windowBackgroundGray': '#000000',
    'actionBarDefault': '#050505',
    'actionBarDefaultSelector': '#121212',
    'actionBarDefaultIcon': '#ffffff',
    'actionBarTabActiveText': '#700000',
    'actionBarTabLine': '#700000',
    'radioBackgroundChecked': '#700000',
    'dialogBackground': '#050505',
    'chat_messagePanelBackground': '#050505',
    'chat_inFileBackground': '#121212',
    'chat_inFileBackgroundSelected': '#700000',
    'chat_inBubble': '#151515',
    'chat_outBubble': '#700000',
    'chat_outBubbleSelected': '#500000',
    'chat_replyPanelClose': '#700000',
    'chats_actionBackground': '#700000',
    'chats_menuBackground': '#050505',
    'chats_archiveBackground': '#121212',
    'chats_archivePinBackground': '#700000',
    'chat_wallpaper': '#000000',
    'avatar_backgroundBlue': '#700000',
    'avatar_backgroundActionBarBlue': '#700000',
    'avatar_backgroundSaved': '#500000',
    'windowBackgroundWhiteBlueText': '#ff3333',
    'windowBackgroundWhiteBlueHeader': '#ff3333',
    'windowBackgroundWhiteInputFieldActivated': '#700000',
    'switchTrackChecked': '#700000',
    'switch2TrackChecked': '#700000',
}

# Convert hex to Android signed integer string
INT_MAPPINGS = {k: str(hex_to_int(v)) for k, v in COLOR_MAPPINGS.items()}

def modify_theme(filepath):
    if not os.path.exists(filepath):
        print(f"Skipping {filepath}, not found.")
        return

    with open(filepath, 'r') as f:
        lines = f.readlines()

    out_lines = []
    for line in lines:
        if '=' in line:
            key, val = line.strip().split('=', 1)
            if key in INT_MAPPINGS:
                out_lines.append(f"{key}={INT_MAPPINGS[key]}\n")
            else:
                out_lines.append(line)
        else:
            out_lines.append(line)

    with open(filepath, 'w') as f:
        f.writelines(out_lines)
    print(f"Patched {filepath}")

if __name__ == '__main__':
    themes = [
        'telegram-android/TMessagesProj/src/main/assets/night.attheme',
        'telegram-android/TMessagesProj/src/main/assets/darkblue.attheme',
        'telegram-android/TMessagesProj/src/main/assets/arctic.attheme',
        'telegram-android/TMessagesProj/src/main/assets/day.attheme'
    ]
    for theme in themes:
        modify_theme(theme)
