# GPU & Hardware Accelerator Support

## Simple Explanation

**XMRig automatically uses the most efficient mining method for your PC.**

- ✅ Auto-detects CPU, NVIDIA GPU, AMD GPU, Intel GPU
- ✅ Uses whichever hardware is fastest
- ✅ No configuration needed
- ✅ Just works

**For Monero (RandomX)**: CPUs are usually 10-20x more efficient than GPUs, so your CPU will do most of the work. GPU provides a small 5-10% boost.

---

## What Hardware is Supported?

- **CPU**: All modern CPUs (primary mining hardware)
- **NVIDIA GPU**: Automatic CUDA support
- **AMD GPU**: Automatic OpenCL support
- **Intel GPU**: Automatic OpenCL support

**Users see hardware breakdown in statistics**:
```
Hardware:
├─ Active: CPU, NVIDIA GPU
├─ CPU: 2,100 H/s (85%)
├─ NVIDIA: 350 H/s (15%)
└─ Total: 2,450 H/s
```

---

## XMRig Binary Requirements

**Download GPU-enabled builds**:
- Windows: `xmrig-6.21.0-msvc-cuda11_7-win64.zip` (includes CUDA + OpenCL)
- Linux: Build with `-DWITH_CUDA=ON -DWITH_OPENCL=ON`
- macOS: OpenCL support included

---

## Configuration (Auto-Generated)

CRYPTOGRAM automatically enables:
- ✅ CPU optimizations (huge pages, AES-NI, assembly)
- ✅ CUDA support (NVIDIA GPUs)
- ✅ OpenCL support (AMD/Intel GPUs)
- ✅ Automatic hardware detection
- ✅ Optimal settings for each device

**No user configuration required.**

---

## Revenue Impact

**Small per-user boost, adds up network-wide:**
- Per user: +5-10% hashrate with GPU
- 10,000 users: +$3,000-6,000/month extra

---

## Summary

**XMRig uses the most efficient mining method for your PC automatically.**

Users get optimal performance without knowing anything about CPUs, GPUs, RandomX algorithms, or mining optimization. It just works.
