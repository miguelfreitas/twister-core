OS X Build Instructions and Notes
====================================
This guide will show you how to build twisterd for OS X.

Notes
-----

* Tested on OS X 10.9.1 on Intel processors only. PPC is not
supported because it is big-endian.
* All of the commands should be executed in a Terminal application. The
built-in one is located in `/Applications/Utilities`.

Preparation
-----------

You need to install Xcode with all the options checked so that the compiler
and everything is available in /usr not just /Developer. Xcode should be
available on your OS X installation media, but if not, you can get the
current version from https://developer.apple.com/xcode/. If you install
Xcode 4.3 or later, you'll need to install its command line tools. This can
be done in `Xcode > Preferences > Downloads > Components` and generally must
be re-done or updated every time Xcode is updated.

There's an assumption that you already have `git` installed, as well. If not,
it's the path of least resistance to install
[GitHub Desktop](https://desktop.github.com/) or
[Git for OS X](https://code.google.com/p/git-osx-installer/). It is also
available via Homebrew or MacPorts.

You will also need to install [Homebrew](http://brew.sh/)
or [MacPorts](https://www.macports.org/) in order to install library
dependencies. It's largely a religious decision which to choose, but I tested only with
Homebrew.

The installation of the actual dependencies is covered in the Instructions
sections below.


Instructions: Homebrew
----------------------

#### Install dependencies using Homebrew

    brew install boost miniupnpc openssl berkeley-db4 autoconf automake libtool

### Building `twisterd`

1. Clone the github tree to get the source code and go into the directory.


        git clone https://github.com/miguelfreitas/twister-core.git
        cd twister-core

2. Build twister using autotool

        ./autotool.sh
        ./configure --enable-logging --with-openssl=/usr/local/opt/openssl --with-libdb=/usr/local/opt/berkeley-db4
        make
(If you have multi core CPU, use "make -j N" where N = the number of your cores)

3. If things go south, before trying again, make sure you clean it up:


        make clean

If all went well, you should now have a twisterd executable in the twister-core directory.
See the Running instructions below.

Instructions: MacPorts (UNTESTED!!)
---------------------------------

### Install dependencies

Installing the dependencies using MacPorts is very straightforward.

    sudo port install boost db48@+no_java openssl miniupnpc libtool

Once installed dependencies, do:

    ./autotool.sh
    ./configure --enable-logging
    make

If things go south, before trying again, make sure you clean it up:

    make clean

Running
-------

It's now available at `./twisterd`, provided that you are still in the `twister-core`
directory. We have to first create the RPC configuration file, though.

Run `./twisterd` to get the filename where it should be put, or just try these
commands:

    mkdir -p "/Users/${USER}/.twister"
    echo -e "rpcuser=user\nrpcpassword=pwd\nrpcallowip=127.0.0.1" > "/Users/${USER}/.twister/twister.conf"
    chmod 600 "/Users/${USER}/.twister/twister.conf"

When next you run it, it will start downloading the blockchain, but it won't
output anything while it's doing this. This process may take several hours. If you see a lonely
`connect: Operation timed out`, don't freak out, it seems to work fine.

Other commands:

    tail -f ~/.twister/debug.log
    ./twisterd --help  # for a list of command-line options.
    ./twisterd -daemon # to start it as a daemon.
    ./twisterd help    # When the daemon is running, to get a list of RPC commands

In order to get the HTML interface, you'll have to download it and link it in .twister:

     git clone https://github.com/miguelfreitas/twister-html.git /Users/${USER}/Library/Application\ Support/twister/html

Once you do that, it will be available at http://localhost:28332/home.html

Troubleshooting
-------
1) You get "DHT network down" in WEB interface on /network.html page
 - Reboot your Mac

