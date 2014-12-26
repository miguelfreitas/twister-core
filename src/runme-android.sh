export PATH=$HOME/android/android-ndk-r8b/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/:$PATH
export NDK=$HOME/android/android-ndk-r8b
export NDK_BASE=$NDK
export SYSROOT=$NDK/platforms/android-9/arch-arm
export BOOSTDIR=$HOME/android/Boost-for-Android/build/
export TARGET_OS=OS_ANDROID_CROSSCOMPILE

export CXX=arm-linux-androideabi-gcc
export CXXFLAGS="-I$SYSROOT/usr/include/ -I$BOOSTDIR/include/boost-1_49 \
 -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/include \
 -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/include \
 -fexceptions -frtti -DHAVE_CXX_STDHEADERS -DANDROID -nostdlib"
export BOOST_LIB_SUFFIX=-gcc-mt-1_49
export BDB_LIB_SUFFIX=-4.8

make -f makefile.android -j2
#make -j2
#exit

#./configure --host=arm-linux-androideabi --enable-shared=no --enable-static=yes\
# CPPFLAGS="-I$SYSROOT/usr/include/ -I$BOOSTDIR/include \
# -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/include \
# -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/include \
# -fexceptions -frtti" \
# LDFLAGS="-Wl,-rpath-link=$SYSROOT/usr/lib/ -L$SYSROOT/usr/lib/ -L$BOOSTDIR/lib \
# $BOOSTDIR/lib/libboost_system-gcc-mt-1_49.a $BOOSTDIR/lib/libboost_thread-gcc-mt-1_49.a \
# $NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/libgnustl_static.a" \
# LIBS="-lc" CFLAGS="-nostdlib" --prefix="$SYSROOT/usr" \
# --with-boost=$BOOSTDIR --with-boost-libdir=$BOOSTDIR/lib  && make -j2
