# 🤖 GitHub Actions - Automated APK Building

**Automated build system for CRYPTOGRAM Android APK**

---

## 📋 Overview

This repository includes a GitHub Actions workflow that automatically builds the CRYPTOGRAM Android APK whenever code is pushed to the repository. The build process includes:

- ✅ Automated compilation of C++ crypto core (NDK)
- ✅ Kotlin/Java compilation
- ✅ APK generation (Debug and Release)
- ✅ Automatic artifact upload
- ✅ Build summary generation

---

## 🚀 Workflow Triggers

The build workflow is triggered automatically on:

### 1. Push Events
```yaml
Branches:
- claude/port-spygram-double-ratchet-*
- main
- master

Paths:
- TMessagesProj/**
- .github/workflows/build-android.yml
```

### 2. Pull Requests
```yaml
Target Branches:
- main
- master

Paths:
- TMessagesProj/**
- .github/workflows/build-android.yml
```

### 3. Manual Trigger
You can manually trigger the workflow from the GitHub Actions tab:
- Go to **Actions** → **Build CRYPTOGRAM Android APK** → **Run workflow**

---

## 🏗️ Build Environment

### Software Versions

| Component | Version |
|-----------|---------|
| **OS** | Ubuntu Latest |
| **Java** | JDK 17 (Temurin) |
| **Android NDK** | 25.2.9519653 |
| **CMake** | 3.22.1 |
| **Gradle** | Wrapper version from project |

### Build Steps

1. **Checkout Code**: Clones repository with submodules
2. **Setup Java**: Installs JDK 17 with Gradle caching
3. **Setup Android SDK**: Installs Android SDK tools
4. **Install NDK**: Downloads and configures Android NDK 25
5. **Install CMake**: Installs CMake 3.22.1 for native builds
6. **Grant Permissions**: Makes gradlew executable
7. **Cache Gradle**: Caches Gradle dependencies for faster builds
8. **Build Debug APK**: Compiles debug version
9. **Build Release APK**: Attempts to compile release (may fail without signing key)
10. **Upload Artifacts**: Uploads APKs to GitHub Actions artifacts
11. **Generate Summary**: Creates build summary with APK details

---

## 📦 Build Outputs

### Debug APK
- **Filename**: `app-debug.apk` (or variant-specific name)
- **Location**: `TMessagesProj/build/outputs/apk/debug/`
- **Signed**: Yes (with debug keystore)
- **Installable**: Yes (on any device with debug mode enabled)
- **Retention**: 30 days on GitHub

### Release APK (Optional)
- **Filename**: `app-release-unsigned.apk`
- **Location**: `TMessagesProj/build/outputs/apk/release/`
- **Signed**: No (requires signing key in secrets)
- **Installable**: No (needs signing)
- **Retention**: 30 days on GitHub

---

## 📥 Downloading APKs

### From GitHub Actions

1. Go to your repository on GitHub
2. Click **Actions** tab
3. Select the completed workflow run
4. Scroll to **Artifacts** section at the bottom
5. Download:
   - `cryptogram-debug-apk` - Debug APK (ready to install)
   - `cryptogram-release-apk` - Release APK (if build succeeded)

### Direct Download URL Pattern
```
https://github.com/SWORDOps/CRYPTOGRAM/actions/runs/[RUN_ID]
```

---

## 🔧 Configuration

### Environment Variables

The workflow uses these environment variables:

```yaml
ANDROID_NDK_HOME: Path to Android NDK installation
ANDROID_NDK: Alias for NDK path
GITHUB_TOKEN: Automatic token for artifact upload
```

### Gradle Configuration

The workflow runs Gradle with:
```bash
./gradlew assembleDebug --stacktrace --no-daemon
```

Flags:
- `--stacktrace`: Shows full error traces if build fails
- `--no-daemon`: Prevents daemon conflicts in CI

---

## 🔐 Release Signing (Optional)

To enable signed release builds, add signing configuration:

### 1. Add Secrets to GitHub

Go to **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Add these secrets:
- `ANDROID_KEYSTORE_FILE` - Base64 encoded keystore file
- `ANDROID_KEYSTORE_PASSWORD` - Keystore password
- `ANDROID_KEY_ALIAS` - Key alias
- `ANDROID_KEY_PASSWORD` - Key password

### 2. Modify Workflow

Add this step before "Build Release APK":

```yaml
- name: Decode Keystore
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: |
    echo "${{ secrets.ANDROID_KEYSTORE_FILE }}" | base64 -d > release.keystore
    echo "KEYSTORE_PATH=../release.keystore" >> $GITHUB_ENV
    echo "KEYSTORE_PASSWORD=${{ secrets.ANDROID_KEYSTORE_PASSWORD }}" >> $GITHUB_ENV
    echo "KEY_ALIAS=${{ secrets.ANDROID_KEY_ALIAS }}" >> $GITHUB_ENV
    echo "KEY_PASSWORD=${{ secrets.ANDROID_KEY_PASSWORD }}" >> $GITHUB_ENV
```

### 3. Update build.gradle

Add signing configuration in `TMessagesProj/build.gradle`:

```gradle
android {
    signingConfigs {
        release {
            if (System.getenv("KEYSTORE_PATH")) {
                storeFile file(System.getenv("KEYSTORE_PATH"))
                storePassword System.getenv("KEYSTORE_PASSWORD")
                keyAlias System.getenv("KEY_ALIAS")
                keyPassword System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}
```

---

## 📊 Build Summary

After each build, the workflow generates a summary showing:

```markdown
## 🔐 CRYPTOGRAM Android Build Summary

### Build Information
- Branch: claude/port-spygram-double-ratchet-011CUqbDVTT7AWYtgAtSGBrs
- Commit: a2d657b
- Build Date: 2025-11-06 12:34:56 UTC

### APK Files Generated
- ✅ Debug APK: app-debug.apk
  - Size: 45.2 MB
- ⏭️ Release APK: Skipped (requires signing key)

### Features Included
- ✅ Signal Protocol (Double Ratchet) for 1-on-1 chats
- ✅ MLS Protocol (RFC 9420) for group chats
- ✅ Military-grade encryption (X25519, Ed25519, AES-256-GCM)
- ✅ Settings UI with toggles
- ✅ Visual indicators (lock icons)
```

---

## 🐛 Troubleshooting

### Build Fails: "CMake not found"

**Problem**: CMake installation failed
**Solution**: Check that CMake version in workflow matches available versions:
```yaml
sdkmanager --list | grep cmake
```

### Build Fails: "NDK not found"

**Problem**: Android NDK not properly installed
**Solution**: Verify NDK version in workflow:
```yaml
sdkmanager --list | grep ndk
```

### Build Fails: "gradlew: Permission denied"

**Problem**: gradlew script not executable
**Solution**: Workflow already handles this, but if needed locally:
```bash
chmod +x TMessagesProj/gradlew
```

### Build Fails: "Execution failed for task ':app:compileDebugKotlin'"

**Problem**: Kotlin compilation error
**Solution**: Check Kotlin version compatibility in `build.gradle`

### Build Succeeds but APK Not Uploaded

**Problem**: APK file not found
**Solution**: Check the "Find APK files" step output for actual APK location

---

## ⚡ Performance Optimization

### Gradle Caching

The workflow caches Gradle dependencies to speed up builds:

```yaml
~/.gradle/caches
~/.gradle/wrapper
```

**Expected build times**:
- First build: 8-12 minutes
- Subsequent builds (with cache): 3-5 minutes

### Parallel Builds

To enable parallel Gradle builds, add to `gradle.properties`:
```properties
org.gradle.parallel=true
org.gradle.workers.max=4
```

---

## 📱 Installing the APK

### From Artifacts

1. Download `cryptogram-debug-apk.zip`
2. Extract `app-debug.apk`
3. Transfer to Android device
4. Enable **Settings** → **Security** → **Install from unknown sources**
5. Open APK file and install

### Using ADB

```bash
# Download APK from GitHub Actions
unzip cryptogram-debug-apk.zip

# Install on connected device
adb install -r app-debug.apk

# Or install on emulator
adb -e install -r app-debug.apk
```

---

## 🔄 Workflow Updates

### Modify Build Configuration

Edit `.github/workflows/build-android.yml`:

```bash
git checkout claude/port-spygram-double-ratchet-011CUqbDVTT7AWYtgAtSGBrs
vim .github/workflows/build-android.yml
git add .github/workflows/build-android.yml
git commit -m "Update build workflow"
git push origin claude/port-spygram-double-ratchet-011CUqbDVTT7AWYtgAtSGBrs
```

### Test Workflow Locally

Use [act](https://github.com/nektos/act) to test workflows locally:

```bash
# Install act
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow
act -j build
```

---

## 📈 Build Status Badge

Add to README.md:

```markdown
![Build Status](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml/badge.svg)
```

Displays: ![Build Status](https://github.com/SWORDOps/CRYPTOGRAM/actions/workflows/build-android.yml/badge.svg)

---

## 🎯 Best Practices

### 1. Keep Dependencies Updated

Regularly update in workflow:
- Java version
- NDK version
- CMake version
- Action versions (@v4, @v3, etc.)

### 2. Monitor Build Times

Check "Job duration" in Actions to identify slow steps:
- If NDK download is slow → cache it
- If Gradle build is slow → increase workers
- If C++ compilation is slow → use ccache

### 3. Secure Secrets

Never commit secrets to repository:
- ✅ Use GitHub Secrets for signing keys
- ✅ Use environment variables for tokens
- ❌ Don't hardcode passwords

### 4. Clean Builds

For clean builds, clear cache:
- Go to **Actions** → **Caches**
- Delete old caches
- Re-run workflow

---

## 🔗 Related Documentation

- **[docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md](docs/implementation/CRYPTOGRAM_ANDROID_COMPLETE.md)** - Full implementation guide
- **[docs/](docs/)** - Build instructions for all platforms
- **[docs/status/FINAL_STATUS.md](docs/status/FINAL_STATUS.md)** - Project status
- **[docs/status/TEST_RESULTS.md](docs/status/TEST_RESULTS.md)** - Test results

---

## 📞 Support

### Build Issues

If builds fail consistently:

1. Check workflow logs in Actions tab
2. Look for error messages in "Build Debug APK" step
3. Verify all dependencies are available
4. Check NDK/CMake compatibility

### Questions

For questions about the build system:
- Check GitHub Actions documentation
- Review workflow YAML comments
- Test locally before pushing

---

## 🎉 Workflow Features

This GitHub Actions workflow provides:

- ✅ **Automated builds** on every push
- ✅ **Multi-ABI support** (armeabi-v7a, arm64-v8a, x86, x86_64)
- ✅ **Native code compilation** (C++ crypto via NDK)
- ✅ **Kotlin/Java compilation**
- ✅ **APK artifact upload** (30-day retention)
- ✅ **Build summaries** with APK details
- ✅ **Release tagging** (automatic release creation)
- ✅ **Gradle caching** for faster builds
- ✅ **Manual triggers** for on-demand builds
- ✅ **Detailed logging** for debugging

---

## 📋 Checklist

Before pushing code:

- [ ] Code compiles locally
- [ ] All tests pass
- [ ] Workflow file is valid YAML
- [ ] Branch name matches pattern
- [ ] Commit message is descriptive

After push:

- [ ] Check Actions tab for workflow run
- [ ] Verify build succeeds
- [ ] Download and test APK
- [ ] Check build summary
- [ ] Verify all artifacts uploaded

---

## 🚀 Quick Start

### Enable Workflow

The workflow is already configured! Just push code:

```bash
git add .
git commit -m "Your changes"
git push origin claude/port-spygram-double-ratchet-011CUqbDVTT7AWYtgAtSGBrs
```

### View Build

1. Go to https://github.com/SWORDOps/CRYPTOGRAM/actions
2. Click on latest workflow run
3. Watch build progress in real-time
4. Download APK from Artifacts when complete

---

**🔐 CRYPTOGRAM Android - Automated Builds**

*Build once, deploy everywhere!* 🚀

---

**Workflow File**: `.github/workflows/build-android.yml`
**Status**: Active
**Last Updated**: 2025-11-06
