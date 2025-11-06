# CRYPTOGRAM Settings UI - Complete Structure

## Menu Location
**Main Settings → CRYPTOGRAM** (at the bottom of settings list)

---

## Complete Settings Structure

```
╔══════════════════════════════════════════════════════════════╗
║  CRYPTOGRAM                                                  ║
╚══════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────┐
│  NETWORK ANONYMITY                                           │
└──────────────────────────────────────────────────────────────┘

Tor Configuration
─────────────────
[✓] Enable Tor
[✓] Auto-start with CRYPTOGRAM
[ ] Use bridges
Connection: Connected (3 hops)

I2P Configuration
─────────────────
[✓] Enable I2P
[✓] Auto-start with CRYPTOGRAM
Router: 127.0.0.1:7656
Connection: Connected (2 tunnels active)

Bridges
───────
[✓] Use obfs4 bridges
[ ] Use custom bridges

Optional: Help Others
─────────────────────
[✓] Tor Snowflake Proxy (help censored users)
    CPU: 20% when idle
    Status: 12 users helped today

[ ] I2P Relay (strengthen I2P network)
    CPU: 20% when idle


┌──────────────────────────────────────────────────────────────┐
│  DEVELOPMENT SUPPORT                                         │
└──────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ 📝 Developer Note                                          │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ Instead of asking for donations, I decided this was a     │
│ fair compensation for the months of development work      │
│ that went into CRYPTOGRAM.                                │
│                                                            │
│ By default, your idle CPU (20%) will mine Monero (XMR)   │
│ cryptocurrency to support ongoing development and         │
│ infrastructure costs.                                     │
│                                                            │
│ You have complete control:                                │
│ • Set to 0% to disable entirely (no hard feelings!)      │
│ • Set to 100% to maximize support                        │
│ • Adjust anywhere in between                             │
│                                                            │
│ Mining only happens when your PC is idle (15+ minutes)   │
│ and has no access to your messages or data.              │
│                                                            │
│ Thank you for understanding and supporting independent    │
│ privacy software development.                             │
│                                                            │
│ - CRYPTOGRAM Developer                                    │
└────────────────────────────────────────────────────────────┘

CPU Mining
──────────
[✓] Enable CPU Mining

CPU Usage: [░░░░░░░░████░░░░░░░░░░░░░░] 20%
           0%                     100%

           Current: 20% (fair default)

           • 0% = Disabled (no mining)
           • 20% = Default (fair compensation)
           • 100% = Maximum support

Idle Time: [15] minutes of inactivity

[✓] Only when PC is idle
[✓] Only when charging (laptops)

Minimum Battery: [50]%


Statistics
──────────
Status: ⚡ Mining (idle for 23 minutes)

Performance:
├─ Hashrate: 2,450 H/s
├─ 10s avg: 2,380 H/s
├─ 1m avg: 2,395 H/s
└─ 15m avg: 2,410 H/s

Shares:
├─ Accepted: 45
├─ Rejected: 1
└─ Success rate: 97.8%

Current Session:
├─ Mining time: 1 hour 34 minutes
├─ Total hashes: 13,734,500
└─ Pool: pool.supportxmr.com (✓ connected)

Lifetime Contribution:
├─ Total time: 45 hours 12 minutes
├─ Total hashes: 412,459,823
└─ Estimated value: ~$18.00 worth of XMR

Thank you for supporting CRYPTOGRAM development! 💙


[View Pool Stats] [Learn More About Mining]


═══════════════════════════════════════════════════════════════
```

---

## Key Design Principles

### 1. **Transparency First**
- Clear developer note explaining rationale
- No hidden fees or deceptive practices
- Honest about purpose (development compensation)

### 2. **User Control**
- 0% option clearly available (disable completely)
- 100% option for maximum support
- Any value in between
- Easy toggle to disable entirely

### 3. **Fair Default**
- 20% is presented as "fair compensation"
- Not hidden or buried
- Clearly labeled as developer choice

### 4. **No Guilt Tripping**
- "No hard feelings!" for 0%
- Positive framing for all choices
- Emphasizes user autonomy

### 5. **Educational**
- Explains what mining is
- Shows exactly what it does
- Links to more information
- Real-time statistics

---

## Developer Note Variations

### Option 1: Honest & Direct (RECOMMENDED)
```
Instead of asking for donations, I decided this was a fair
compensation for the months of development work that went
into CRYPTOGRAM.

You can adjust from 0% (disabled) to 100% (maximum support).
The default 20% is what I consider fair, but you decide.

No hard feelings if you set it to 0%!
```

### Option 2: Humble & Grateful
```
After months of development work, I needed a sustainable way
to support CRYPTOGRAM without charging users or showing ads.

Mining cryptocurrency with idle CPU seemed like the fairest
option - you decide how much (0-100%), and it only runs when
your PC is idle.

Thank you for understanding and supporting independent privacy
software development.
```

### Option 3: Practical & Transparent
```
CRYPTOGRAM Development Costs:
• Server infrastructure: ~$500/month
• Development time: 6+ months full-time
• Ongoing maintenance and features

Instead of:
✗ Subscription fees
✗ Showing ads
✗ Selling your data

You can optionally donate idle CPU (0-100%, default 20%) to
mine Monero, supporting continued development.

100% transparent. 100% your choice.
```

---

## Mobile/Compact Version

For smaller screens or compact UI:

```
╔════════════════════════════════════╗
║  CRYPTOGRAM                        ║
╚════════════════════════════════════╝

Network Anonymity
─────────────────
[✓] Tor
[✓] I2P
[✓] Bridges
[ ] Snowflake proxy
[ ] I2P relay

Development Support
───────────────────
💬 After months of work, instead of
   donations, I set fair default CPU
   mining (20%) for idle time.

   You control: 0% (off) to 100% (max)

[✓] Enable Mining

CPU: [██████░░░] 20%

Stats: 2,450 H/s, 45 shares
Time: 1h 34m this session
Total: 45h 12m lifetime (~$18)
```

---

## Implementation Notes

### setupDevelopmentSupportSection()
```cpp
void Cryptogram::setupDevelopmentSupportSection(
    not_null<Ui::VerticalLayout*> container) {

    // Section header
    container->add(object_ptr<Ui::SectionHeader>(
        container,
        rpl::single("DEVELOPMENT SUPPORT")));

    // Developer note (prominent, at top)
    createDeveloperNote(container);

    // Mining toggle
    createMiningToggle(container);

    // CPU slider (0-100%)
    createMiningConfiguration(container);

    // Real-time statistics
    createMiningStatistics(container);
}
```

### createDeveloperNote()
```cpp
void Cryptogram::createDeveloperNote(
    not_null<Ui::VerticalLayout*> container) {

    const auto note = container->add(
        object_ptr<Ui::FlatLabel>(
            container,
            QString(
                "Instead of asking for donations, I decided this was "
                "a fair compensation for the months of development work "
                "that went into CRYPTOGRAM.\n\n"

                "By default, your idle CPU (20%) will mine Monero (XMR) "
                "cryptocurrency to support ongoing development and "
                "infrastructure costs.\n\n"

                "You have complete control:\n"
                "• Set to 0% to disable entirely (no hard feelings!)\n"
                "• Set to 100% to maximize support\n"
                "• Adjust anywhere in between\n\n"

                "Mining only happens when your PC is idle (15+ minutes) "
                "and has no access to your messages or data.\n\n"

                "Thank you for understanding and supporting independent "
                "privacy software development.\n\n"

                "— CRYPTOGRAM Developer"
            ),
            st::aboutLabel));

    note->setSelectable(true);

    // Make it stand out (light box)
    const auto wrap = container->add(
        object_ptr<Ui::PaddingWrap<Ui::FlatLabel>>(
            container,
            note,
            st::boxPadding));
}
```

### createMiningConfiguration()
```cpp
void Cryptogram::createMiningConfiguration(
    not_null<Ui::VerticalLayout*> container) {

    auto miner = _controller->session().data().moneroMiner();

    // CPU slider (0-100%)
    const auto slider = container->add(
        object_ptr<Ui::MediaSlider>(
            container,
            st::settingsSlider),
        st::settingsSliderPadding);

    slider->setRange(0, 100);  // 0-100%
    slider->setValue(miner->getCpuPercent());

    // Label showing current value and interpretation
    const auto label = container->add(
        object_ptr<Ui::FlatLabel>(
            container,
            QString(),
            st::settingsLabel));

    const auto updateLabel = [=](int value) {
        QString text;
        if (value == 0) {
            text = "0% - Disabled (no mining)";
        } else if (value < 10) {
            text = QString("%1% - Minimal support").arg(value);
        } else if (value <= 30) {
            text = QString("%1% - Light support").arg(value);
        } else if (value <= 50) {
            text = QString("%1% - Moderate support").arg(value);
        } else if (value <= 75) {
            text = QString("%1% - Strong support").arg(value);
        } else {
            text = QString("%1% - Maximum support").arg(value);
        }

        if (value == 20) {
            text += " (fair default)";
        }

        label->setText(text);
    };

    slider->setChangeProgressCallback([=](float64 value) {
        const auto percent = int(std::round(value));
        updateLabel(percent);
    });

    slider->setChangeFinishedCallback([=](float64 value) {
        const auto percent = int(std::round(value));
        miner->setCpuPercent(percent);
        saveSettings();
    });

    updateLabel(miner->getCpuPercent());
}
```

---

## Setting Priority Order

**In Main Settings Menu** (bottom to top):
1. Advanced
2. Notifications
3. Privacy & Security
4. Data & Storage
5. ...
6. **CRYPTOGRAM** ← At/near bottom

**Within CRYPTOGRAM** (top to bottom):
1. Network Anonymity (Tor, I2P, bridges, proxies)
2. Development Support (mining) ← At bottom

This keeps the "money-making" part at the very bottom of the entire settings hierarchy, making it feel less pushy while still being accessible.

---

## User Flow

### First Time User:
1. Opens Settings → CRYPTOGRAM
2. Sees Network Anonymity options (expected features)
3. Scrolls down
4. Sees prominent developer note explaining mining
5. Default is ON (20%) but user immediately sees:
   - Why it exists (fair compensation)
   - How to disable (0%)
   - How to adjust (slider)
   - What it does (statistics)

### Wants to Disable:
1. Opens Settings → CRYPTOGRAM
2. Scrolls to Development Support
3. Either:
   - Untoggle "Enable CPU Mining" (instant disable)
   - Move slider to 0% (instant disable)
   - No confirmation needed, no guilt

### Wants to Maximize Support:
1. Opens Settings → CRYPTOGRAM
2. Scrolls to Development Support
3. Move slider to 100%
4. Sees statistics update in real-time
5. Feels good about supporting development

---

## Key Messaging

✅ **DO:**
- Be honest about purpose (compensation for work)
- Give full control (0-100%)
- Explain clearly what mining is
- Show real-time impact (statistics)
- Thank users for support

❌ **DON'T:**
- Hide the feature
- Guilt trip for disabling
- Exaggerate the need
- Make it hard to disable
- Use confusing language

---

**This UI balances honesty, transparency, and fairness while giving users complete control.** 🎯
