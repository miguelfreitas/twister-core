Release Process
====================

* update translations (ping wumpus, Diapolo or tcatm on IRC)
* see https://github.com/bitcoin/bitcoin/blob/master/doc/translation_process.md#syncing-with-transifex

* * *

###update (commit) version in sources

	doc/README*
	src/clientversion.h (change CLIENT_VERSION_IS_RELEASE to true)

###tag version in git

	git tag -s v(new version, e.g. 0.8.0)

###write release notes. git shortlog helps a lot, for example:

	git shortlog --no-merges v(current version, e.g. 0.7.2)..v(new version, e.g. 0.8.0)

* * *

###perform gitian builds

 From a directory containing the twister source, gitian-builder and gitian.sigs
  
#	export SIGNER=(your gitian key, ie bluematt, sipa, etc)
	export VERSION=(new version, e.g. 0.8.0)
	pushd ./twister-core
	git checkout v${VERSION}
	popd
	pushd ./gitian-builder

###fetch and build inputs: (first time, or when dependency versions change)
 
	mkdir -p inputs; cd inputs/

 Register and download the Apple SDK: (see OSX Readme for details)
 
 https://developer.apple.com/downloads/download.action?path=Developer_Tools/xcode_4.6.3/xcode4630916281a.dmg
 
 Using a Mac, create a tarball for the 10.7 SDK and copy it to the inputs directory:
 
	tar -C /Volumes/Xcode/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/ -czf MacOSX10.7.sdk.tar.gz MacOSX10.7.sdk

 Download remaining inputs, and build everything:
 
	wget 'https://www.openssl.org/source/openssl-1.0.1h.tar.gz'
	wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
	wget 'http://zlib.net/zlib-1.2.8.tar.gz'
	wget 'https://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2'
	wget 'https://svn.boost.org/trac/boost/raw-attachment/ticket/7262/boost-mingw.patch' -O boost-mingw-gas-cross-compile-2013-03-03.patch
	wget 'https://protobuf.googlecode.com/files/protobuf-2.5.0.tar.bz2'
	wget 'https://github.com/mingwandroid/toolchain4/archive/10cc648683617cca8bcbeae507888099b41b530c.tar.gz'
	wget 'http://www.opensource.apple.com/tarballs/cctools/cctools-809.tar.gz'
	wget 'http://www.opensource.apple.com/tarballs/dyld/dyld-195.5.tar.gz'
	wget 'http://www.opensource.apple.com/tarballs/ld64/ld64-127.2.tar.gz'
	wget 'https://github.com/theuni/libdmg-hfsplus/archive/libdmg-hfsplus-v0.1.tar.gz'
	wget 'http://llvm.org/releases/3.2/clang+llvm-3.2-x86-linux-ubuntu-12.04.tar.gz' -O clang-llvm-3.2-x86-linux-ubuntu-12.04.tar.gz
	cd ..
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/boost-linux.yml
	mv build/out/boost-*.zip inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/deps-linux.yml
	mv build/out/twister-deps-*.zip inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/boost-win.yml
	mv build/out/boost-*.zip inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/deps-win.yml
	mv build/out/twister-deps-*.zip inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/protobuf-win.yml
	mv build/out/protobuf-*.zip inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/gitian-osx-native.yml
	mv build/out/osx-*.tar.gz inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/gitian-osx-depends.yml
	mv build/out/osx-*.tar.gz inputs/
	./bin/gbuild ../twister-core/contrib/gitian-descriptors/gitian-osx-qt.yml
	mv build/out/osx-*.tar.gz inputs/

 The expected SHA256 hashes of the intermediate inputs are:

    f29b7d9577417333fb56e023c2977f5726a7c297f320b175a4108cf7cd4c2d29  boost-linux32-1.55.0-gitian-r1.zip
    88232451c4104f7eb16e469ac6474fd1231bd485687253f7b2bdf46c0781d535  boost-linux64-1.55.0-gitian-r1.zip
    60dc2d3b61e9c7d5dbe2f90d5955772ad748a47918ff2d8b74e8db9b1b91c909  boost-win32-1.55.0-gitian-r6.zip
    f65fcaf346bc7b73bc8db3a8614f4f6bee2f61fcbe495e9881133a7c2612a167  boost-win64-1.55.0-gitian-r6.zip
    e2e403e1a08869c7eed4d4293bce13d51ec6a63592918b90ae215a0eceb44cb4  protobuf-win32-2.5.0-gitian-r4.zip
    a0999037e8b0ef9ade13efd88fee261ba401f5ca910068b7e0cd3262ba667db0  protobuf-win64-2.5.0-gitian-r4.zip


 Build twister-core for Linux, Windows, and OS X:
  
#	./bin/gbuild --commit twister-core=v${VERSION} ../twister-core/contrib/gitian-descriptors/gitian-win.yml
	./bin/gbuild --commit twister-core=HEAD ../twister-core/contrib/gitian-descriptors/gitian-win.yml
#	./bin/gsign --signer $SIGNER --release ${VERSION}-win --destination ../gitian.sigs/ ../bitcoin/contrib/gitian-descriptors/gitian-win.yml
	pushd build/out
	zip -r bitcoin-${VERSION}-win-gitian.zip *
	mv bitcoin-${VERSION}-win-gitian.zip ../../../
	popd

  Build output expected:

#  1. linux 32-bit and 64-bit binaries + source (bitcoin-${VERSION}-linux-gitian.zip)
  2. windows 32-bit and 64-bit binaries + installer + source (bitcoin-${VERSION}-win-gitian.zip)
#  3. OSX installer (Bitcoin-Qt.dmg)
#  4. Gitian signatures (in gitian.sigs/${VERSION}-<linux|win|osx>/(your gitian key)/

repackage gitian builds for release as stand-alone zip/tar/installer exe

###Next steps:


