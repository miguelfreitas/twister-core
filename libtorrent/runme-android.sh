export PATH=$HOME/android/android-ndk-r8b/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/:$PATH
export NDK=$HOME/android/android-ndk-r8b
export NDK_BASE=$NDK
export SYSROOT=$NDK/platforms/android-9/arch-arm
export BOOSTDIR=$HOME/android/Boost-for-Android/build/

if [ $1 == "configure" ]; then
if [ ! -f configure ]; then
  ./bootstrap.sh
fi
./configure --host=arm-linux-androideabi --enable-shared=no --enable-static=yes \
 --enable-debug \
 CPPFLAGS="-I$SYSROOT/usr/include/ -I$BOOSTDIR/include \
 -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/include \
 -I$NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/include \
 -fexceptions -frtti -DANDROID" \
 LDFLAGS="-Wl,-rpath-link=$SYSROOT/usr/lib/ -L$SYSROOT/usr/lib/ -L$BOOSTDIR/lib \
 $BOOSTDIR/lib/libboost_system-gcc-mt-1_49.a $BOOSTDIR/lib/libboost_thread-gcc-mt-1_49.a \
 $NDK_BASE/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/libgnustl_static.a" \
 LIBS="-lc -lssl -lcrypto" CFLAGS="-nostdlib" --prefix="$SYSROOT/usr" \
 --with-boost=$BOOSTDIR --with-boost-libdir=$BOOSTDIR/lib  && make -j2
fi

make -j2

