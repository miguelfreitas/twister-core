ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
  COPYING twister-control.py
  
dist_doc_DATA = README.md

LIBLEVELDB = src/leveldb/libleveldb.a
LIBMEMENV  = src/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(CXXFLAGS) $(CPPFLAGS)"

bin_PROGRAMS = twisterd
bin_SCRIPTS = twister-control

KADEMLIA_SOURCES = \
  libtorrent/src/kademlia/dht_tracker.cpp      \
  libtorrent/src/kademlia/find_data.cpp        \
  libtorrent/src/kademlia/dht_get.cpp          \
  libtorrent/src/kademlia/node.cpp             \
  libtorrent/src/kademlia/node_id.cpp          \
  libtorrent/src/kademlia/refresh.cpp          \
  libtorrent/src/kademlia/routing_table.cpp    \
  libtorrent/src/kademlia/rpc_manager.cpp      \
  libtorrent/src/kademlia/logging.cpp          \
  libtorrent/src/kademlia/traversal_algorithm.cpp

if WITH_SHIPPED_GEOIP
GEOIP_SOURCES = libtorrent/src/GeoIP.c
endif

if WITH_OPENSSL
ASIO_OPENSSL_SOURCES = libtorrent/src/asio_ssl.cpp
endif

LIBTORRENT_SOURCES = \
  libtorrent/src/web_connection_base.cpp     \
  libtorrent/src/alert.cpp                       \
  libtorrent/src/alert_manager.cpp               \
  libtorrent/src/allocator.cpp                   \
  libtorrent/src/asio.cpp                        \
  libtorrent/src/assert.cpp                      \
  libtorrent/src/bandwidth_limit.cpp             \
  libtorrent/src/bandwidth_manager.cpp           \
  libtorrent/src/bandwidth_queue_entry.cpp       \
  libtorrent/src/bloom_filter.cpp                \
  libtorrent/src/broadcast_socket.cpp            \
  libtorrent/src/bt_peer_connection.cpp          \
  libtorrent/src/chained_buffer.cpp              \
  libtorrent/src/connection_queue.cpp            \
  libtorrent/src/ConvertUTF.cpp                  \
  libtorrent/src/create_torrent.cpp              \
  libtorrent/src/disk_buffer_holder.cpp          \
  libtorrent/src/disk_buffer_pool.cpp            \
  libtorrent/src/disk_io_thread.cpp              \
  libtorrent/src/entry.cpp                       \
  libtorrent/src/enum_net.cpp                    \
  libtorrent/src/error_code.cpp                  \
  libtorrent/src/escape_string.cpp               \
  libtorrent/src/file.cpp                        \
  libtorrent/src/file_pool.cpp                   \
  libtorrent/src/file_storage.cpp                \
  libtorrent/src/gzip.cpp                        \
  libtorrent/src/hasher.cpp                      \
  libtorrent/src/http_connection.cpp             \
  libtorrent/src/http_parser.cpp                 \
  libtorrent/src/http_seed_connection.cpp        \
  libtorrent/src/http_stream.cpp                 \
  libtorrent/src/http_tracker_connection.cpp     \
  libtorrent/src/i2p_stream.cpp                  \
  libtorrent/src/identify_client.cpp             \
  libtorrent/src/instantiate_connection.cpp      \
  libtorrent/src/ip_filter.cpp                   \
  libtorrent/src/ip_voter.cpp                    \
  libtorrent/src/lazy_bdecode.cpp                \
  libtorrent/src/logger.cpp                      \
  libtorrent/src/lsd.cpp                         \
  libtorrent/src/lt_trackers.cpp                 \
  libtorrent/src/magnet_uri.cpp                  \
  libtorrent/src/metadata_transfer.cpp           \
  libtorrent/src/mpi.c                           \
  libtorrent/src/natpmp.cpp                      \
  libtorrent/src/parse_url.cpp                   \
  libtorrent/src/pe_crypto.cpp                   \
  libtorrent/src/peer_connection.cpp             \
  libtorrent/src/piece_picker.cpp                \
  libtorrent/src/packet_buffer.cpp               \
  libtorrent/src/policy.cpp                      \
  libtorrent/src/puff.cpp                        \
  libtorrent/src/random.cpp                      \
  libtorrent/src/rsa.cpp                         \
  libtorrent/src/rss.cpp                         \
  libtorrent/src/session.cpp                     \
  libtorrent/src/session_impl.cpp                \
  libtorrent/src/settings.cpp                    \
  libtorrent/src/smart_ban.cpp                   \
  libtorrent/src/socket_io.cpp                   \
  libtorrent/src/socket_type.cpp                 \
  libtorrent/src/socks5_stream.cpp               \
  libtorrent/src/stat.cpp                        \
  libtorrent/src/storage.cpp                     \
  libtorrent/src/string_util.cpp                 \
  libtorrent/src/thread.cpp                      \
  libtorrent/src/torrent.cpp                     \
  libtorrent/src/torrent_handle.cpp              \
  libtorrent/src/torrent_info.cpp                \
  libtorrent/src/time.cpp                        \
  libtorrent/src/timestamp_history.cpp           \
  libtorrent/src/tracker_manager.cpp             \
  libtorrent/src/udp_socket.cpp                  \
  libtorrent/src/udp_tracker_connection.cpp      \
  libtorrent/src/upnp.cpp                        \
  libtorrent/src/ut_metadata.cpp                 \
  libtorrent/src/ut_pex.cpp                      \
  libtorrent/src/utf8.cpp                        \
  libtorrent/src/utp_socket_manager.cpp          \
  libtorrent/src/utp_stream.cpp                  \
  libtorrent/src/web_peer_connection.cpp         \
  \
  $(KADEMLIA_SOURCES)             \
  $(GEOIP_SOURCES)                \
  $(ASIO_OPENSSL_SOURCES)

if USE_SSE2
SSE2_SOURCES = src/scrypt-sse2.cpp
endif

if ENABLE_RSS
RSS_SOURCES = src/twister_rss.cpp
endif

BITCOIN_TWISTER_SOURCES = \
    src/alert.cpp \
    src/version.cpp \
    src/checkpoints.cpp \
    src/netbase.cpp \
    src/addrman.cpp \
    src/crypter.cpp \
    src/key.cpp \
    src/db.cpp \
    src/init.cpp \
    src/bitcoind.cpp \
    src/keystore.cpp \
    src/core.cpp \
    src/main.cpp \
    src/net.cpp \
    src/protocol.cpp \
    src/bitcoinrpc.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcwallet.cpp \
    src/rpcblockchain.cpp \
    src/rpcrawtransaction.cpp \
    src/script.cpp \
    src/scrypt.cpp \
    src/softcheckpoint.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/wallet.cpp \
    src/walletdb.cpp \
    src/hash.cpp \
    src/bloom.cpp \
    src/noui.cpp \
    src/leveldb.cpp \
    src/txdb.cpp \
    src/chainparams.cpp \
    src/dhtproxy.cpp \
    src/twister.cpp \
    src/twister_utils.cpp \
    $(SSE2_SOURCES) \
    $(RSS_SOURCES)

twisterd_SOURCES = $(LIBTORRENT_SOURCES) $(BITCOIN_TWISTER_SOURCES)

twisterd_LDFLAGS = @OPENSSL_LDFLAGS@ @DB_CXX_LDFLAGS@

twisterd_DEPENDENCIES = $(LIBLEVELDB) $(LIBMEMENV)

twisterd_LDADD = $(LIBLEVELDB) $(LIBMEMENV) \
    @BOOST_SYSTEM_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_CHRONO_LIB@ @BOOST_LOCALE_LIB@ \
    @BOOST_REGEX_LIB@ @BOOST_LDFLAGS@ @DB_CXX_LIBS@ @OPENSSL_LIBS@

AM_CPPFLAGS = -ftemplate-depth-100 -DBOOST_SPIRIT_THREADSAFE -D_FILE_OFFSET_BITS=64 \
    -I$(top_srcdir)/libtorrent/include \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/src/leveldb/include -I$(top_srcdir)/src/leveldb/helpers \
    @DEBUGFLAGS@ @BOOST_CPPFLAGS@ @OPENSSL_INCLUDES@ @DB_CXX_CPPFLAGS@

AM_LDFLAGS = @OPENSSL_LDFLAGS@

twister-control: twister-control.py Makefile
	cat < $(srcdir)/twister-control.py > twister-control
	chmod +x twister-control

CLEANFILES = $(LIBLEVELDB) $(LIBMEMENV) $(bin_SCRIPTS) $(bin_PROGRAMS)

clean-local:
	-$(MAKE) -C src/leveldb clean
	rm -f src/leveldb/*/*.gcno src/leveldb/helpers/memenv/*.gcno

cppcheck:
	cppcheck ./src -j 4 --force --quiet --suppressions ./src/cppcheck-suppressions.txt

pixmapsdir = $(datadir)/pixmaps
pixmaps_DATA = share/pixmaps/*

desktopdir = $(datadir)/applications
desktop_DATA = share/applications/twister.desktop share/applications/twister-control.desktop

UPDATE_DESKTOP = update-desktop-database $(datadir)/applications || :

install-data-hook: 
	$(UPDATE_DESKTOP)
uninstall-hook: 
	$(UPDATE_DESKTOP)
