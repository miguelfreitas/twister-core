#twister building script for IOS on linux

export IPHONE_IP=""
export IOS_SDK=/usr/share/iPhoneOS6.0.sdk
export ARCH=armv7
export TARGET=arm-apple-darwin11
export LINKER_VER=236.3
export IPHONEOS_DEPLOYMENT_TARGET=6.0
export IOS_SIGN_CODE_WHEN_BUILD=1
export TARGET_OS=IOS
export PJC=2

export CC="clang"
export CXX="clang++"
export CFLAGS="-target $TARGET -arch $ARCH -isysroot $IOS_SDK -fblocks -fobjc-arc -g0 -O2 -D$TARGET_OS -mlinker-version=$LINKER_VER"
export CXXFLAGS="$CFLAGS"
export LD="$TARGET-ld"
export AR="$TARGET-ar"

export LDFLAGS="-L$IOS_SDK/System"

mkdir -p ios-build/ext
cd ios-build/ext
echo 'Downloading leveldb...'
[ -f leveldb.zip ] || wget https://github.com/google/leveldb/archive/master.zip -O leveldb.zip
[ -d leveldb-master ] || unzip leveldb.zip
cd leveldb-master
cat << _EOF > makefile.ios
SOURCES=db/builder.cc db/c.cc db/dbformat.cc db/db_impl.cc db/db_iter.cc db/dumpfile.cc db/filename.cc db/log_reader.cc db/log_writer.cc db/memtable.cc db/repair.cc db/table_cache.cc db/version_edit.cc db/version_set.cc db/write_batch.cc table/block_builder.cc table/block.cc table/filter_block.cc table/format.cc table/iterator.cc table/merger.cc table/table_builder.cc table/table.cc table/two_level_iterator.cc util/arena.cc util/bloom.cc util/cache.cc util/coding.cc util/comparator.cc util/crc32c.cc util/env.cc util/env_posix.cc util/filter_policy.cc util/hash.cc util/histogram.cc util/logging.cc util/options.cc util/status.cc  port/port_posix.cc
MEMENV_SOURCES=helpers/memenv/memenv.cc
PLATFORM_CCFLAGS= -DOS_MACOSX -DLEVELDB_PLATFORM_POSIX
PLATFORM_CXXFLAGS= -DOS_MACOSX -DLEVELDB_PLATFORM_POSIX
CFLAGS += -I. -I./include \$(PLATFORM_CCFLAGS) -O2 -DNDEBUG
CXXFLAGS += -I. -I./include \$(PLATFORM_CXXFLAGS) -O2 -DNDEBUG
LIBOBJECTS = \$(SOURCES:.cc=.o)
MEMENVOBJECTS = \$(MEMENV_SOURCES:.cc=.o)
LIBRARY = libleveldb.a
MEMENVLIBRARY = libmemenv.a

default: all

all: \$(LIBRARY) \$(MEMENVLIBRARY)

clean:
	rm -f \$(LIBRARY) \$(MEMENVLIBRARY) */*.o */*/*.o ios-x86/*/*.o ios-arm/*/*.o build_config.mk
	rm -rf ios-x86/* ios-arm/*

\$(LIBRARY): \$(LIBOBJECTS)
	rm -f \$@
	\$(AR) -rs \$@ \$(LIBOBJECTS)

\$(MEMENVLIBRARY) : \$(MEMENVOBJECTS)
	rm -f \$@
	\$(AR) -rs \$@ \$(MEMENVOBJECTS)

.cc.o:
	\$(CXX) \$(CXXFLAGS) -c \$< -o \$@

.c.o:
	\$(CC) \$(CFLAGS) -c \$< -o \$@
_EOF

make -f makefile.ios -j$PJC 
cd ..

echo 'Downloading berkeley db...'
[ -f db-5.3.28.tar.gz ] || wget http://download.oracle.com/berkeley-db/db-5.3.28.tar.gz
[ -d db-5.3.28 ] || tar xf db-5.3.28.tar.gz
cd db-5.3.28/build_unix
export _CFLAGS="$CFLAGS"
export _CXXFLAGS="$CXXFLAGS"
export CFLAGS="-pipe -gdwarf-2 -no-cpp-precomp -mthumb $_CFLAGS"
export CXXFLAGS="-pipe -gdwarf-2 -no-cpp-precomp -mthumb $_CXXFLAGS"
../dist/configure --host=$TARGET --prefix=/usr --enable-compat185 --enable-shared=no --enable-static --enable-cxx --enable-dbm --enable-st
make -j$PJC

export CFLAGS="$_CFLAGS"
export CXXFLAGS="$_CXXFLAGS"

cd ../..

echo 'Downloading boost...'
[ -f boost_1_58_0.tar.bz2 ] || wget https://downloads.sourceforge.net/project/boost/boost/1.58.0/boost_1_58_0.tar.bz2
[ -d boost_1_58_0 ] || tar xf boost_1_58_0.tar.bz2

cd ../..

echo 'Building libtorrent...'
[ -f ../libtorrent/src/ios-build/libtorrent-rasterbar.a ] || make -C ../libtorrent/src -f makefile.ios -j$PJC

echo 'Building twister...'
make -f makefile.ios -j$PJC

echo "Installing twisterd to your device..."
[ -n "$IPHONE_IP" ] && make -f makefile.ios install
