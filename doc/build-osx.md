Mac OS X Build Instructions and Notes
====================================
This guide will show you how to build twisterd for OSX.

Notes
-----

* Tested on OS X 10.9.1 on Intel processors only. PPC is not
supported because it is big-endian.
* All of the commands should be executed in a Terminal application. The
built-in one is located in `/Applications/Utilities`.

Preparation
-----------

You need to install XCode with all the options checked so that the compiler
and everything is available in /usr not just /Developer. XCode should be
available on your OS X installation media, but if not, you can get the
current version from https://developer.apple.com/xcode/. If you install
Xcode 4.3 or later, you'll need to install its command line tools. This can
be done in `Xcode > Preferences > Downloads > Components` and generally must
be re-done or updated every time Xcode is updated.

There's an assumption that you already have `git` installed, as well. If
not, it's the path of least resistance to install [Github for Mac](https://mac.github.com/)
(OS X 10.7+) or
[Git for OS X](https://code.google.com/p/git-osx-installer/). It is also
available via Homebrew or MacPorts.

You will also need to install [Homebrew](http://mxcl.github.io/homebrew/)
or [MacPorts](https://www.macports.org/) in order to install library
dependencies. It's largely a religious decision which to choose, but I tested only with 
Homebrew.

The installation of the actual dependencies is covered in the Instructions
sections below.


Instructions: HomeBrew
----------------------

#### Install dependencies using Homebrew

        brew install boost miniupnpc openssl berkeley-db4

Note: After you have installed the dependencies, you should check that the Brew-installed 
version of OpenSSL is the one available for compilation. You can check this by typing

        openssl version

into Terminal. You should see OpenSSL 1.0.1e 11 Feb 2013.

If that's not the case, you *could* `brew link --force openssl` but it's a bad idea. 
Instead, it's enough to make sure the right openssl binary is on your $PATH:

        export PATH=/usr/local/opt/openssl/bin:$PATH

### Building `twisterd`

1. Clone the github tree to get the source code and go into the directory.

        git clone git@github.com:miguelfreitas/twister-core.git
        cd twister-core

2. Set system variables to match your environment. THIS IS IMPORTANT!
        
        export OPENSSL_INCLUDE_PATH=/usr/local/opt/openssl/include
        export OPENSSL_LIB_PATH=/usr/local/opt/openssl/lib
        export BDB_INCLUDE_PATH=/usr/local/opt/berkeley-db4/include
        export BDB_LIB_PATH=/usr/local/opt/berkeley-db4/lib
        export BOOST_INCLUDE_PATH=/usr/local/opt/boost/include
        export BOOST_LIB_PATH=/usr/local/opt/boost/lib
        export BOOST_LIB_SUFFIX=-mt
        export LDFLAGS="-L$OPENSSL_LIB_PATH -L$BDB_LIB_PATH -L$BOOST_LIB_PATH"
        export CPPFLAGS="-I$OPENSSL_INCLUDE_PATH -I$BDB_INCLUDE_PATH -I$BOOST_INCLUDE_PATH"

3. Build libtorrent

        cd libtorrent
        ./bootstrap.sh
        ./configure --enable-logging --enable-debug --enable-dht
        make
        # note: install is optional, might conflict with existing libtorrent install
        make install  

4. Build twisterd. Note: it *will* emit a lot of warnings, but as long as you don't get 
actual `error` messages, it should be fine:

        cd ../
        cd src
        make -f makefile.osx

5.  It is a good idea to build and run the unit tests, too:

        make -f makefile.osx test

If things go south, before trying again, make sure you clean it up:

        make -f makefile.osx clean


If all went well, you should now have a twisterd executable in the src directory. 
See the Running instructions below.

Instructions: MacPorts (UNTESTED!!)
---------------------------------

### Install dependencies

Installing the dependencies using MacPorts is very straightforward.

    sudo port install boost db48@+no_java openssl miniupnpc

### Building `twisterd`

1. Clone the github tree to get the source code and go into the directory.

        git clone git@github.com:miguelfreitas/twister-core.git
        cd twister-core

2.  Build twisterd:

        cd src
        make -f makefile.osx

3.  It is a good idea to build and run the unit tests, too:

        make -f makefile.osx test

Running
-------

It's now available at `./twisterd`, provided that you are still in the `src`
directory. We have to first create the RPC configuration file, though.

Run `./twisterd` to get the filename where it should be put, or just try these
commands:

    echo -e "rpcuser=user\nrpcpassword=pwd" > "/Users/${USER}/.twister/twister.conf"
    chmod 600 "/Users/${USER}/.twister/twister.conf"

When next you run it, it will start downloading the blockchain, but it won't
output anything while it's doing this. This process may take several hours. If you see a lonely 
`connect: Operation timed out`, don't freak out, it seems to work fine.

Other commands:

    ./twisterd --help  # for a list of command-line options.
    ./twisterd -daemon # to start it as a daemon.
    ./twisterd help    # When the daemon is running, to get a list of RPC commands

In order to get the HTML interface, you'll have to download it and link it in .twister:

	git clone git@github.com:miguelfreitas/twister-html.git
	ln -s twister-html /Users/${USER}/.twister/html
