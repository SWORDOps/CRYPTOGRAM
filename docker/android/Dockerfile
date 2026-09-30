# CRYPTOGRAM Android build container.
#
# JDK 21 (verified with Gradle 8.7 / AGP 8.6.1) + the exact SDK/NDK
# component set pinned by TMessagesProj/build.gradle:
#   compileSdk 35 / targetSdk 35 / ndkVersion "27.2.12479018"
#
# Build image:
#   docker build -t cryptogram-build:android docker/android
# Build the app (mount the monorepo):
#   docker run --rm -v "$PWD":/src -w /src/telegram-android \
#     cryptogram-build:android bash -c '
#       echo "sdk.dir=/opt/android-sdk" > TMessagesProj/local.properties &&
#       ./gradlew :TMessagesProj_App:assembleAfatDebug --no-daemon'
#
# NOTE: the Android SDK is license-restricted — install at image BUILD
# time from Google's repo for LOCAL use; do not push this image to a
# public registry.

FROM eclipse-temurin:21-jdk

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=$ANDROID_HOME
ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
ENV ANDROID_NDK_ROOT=$ANDROID_HOME/ndk/27.2.12479018
ENV PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip zip ca-certificates git file \
    && rm -rf /var/lib/apt/lists/*

# cmdline-tools
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -sSLo /tmp/cmdtools.zip \
       https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -qo /tmp/cmdtools.zip -d ${ANDROID_HOME}/cmdline-tools \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools \
          ${ANDROID_HOME}/cmdline-tools/latest \
    && rm /tmp/cmdtools.zip

# SDK components: platform 35 (compileSdk/targetSdk), build-tools 35.0.0,
# NDK 27.2.12479018 (ndkVersion from build.gradle — NOT the 25.x default
# in build_android.sh).
RUN yes | ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager --licenses \
    > /dev/null \
    && ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager \
       "platform-tools" \
       "platforms;android-35" \
       "build-tools;35.0.0" \
       "ndk;27.2.12479018" \
    > /dev/null \
    && rm -rf ${ANDROID_HOME}/.temp

WORKDIR /src
