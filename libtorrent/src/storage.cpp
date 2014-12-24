/*

Copyright (c) 2003-2012, Arvid Norberg, Daniel Wallin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "libtorrent/pch.hpp"

#include <ctime>
#include <algorithm>
#include <set>
#include <functional>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/ref.hpp>
#include <boost/bind.hpp>
#include <boost/version.hpp>
#include <boost/scoped_array.hpp>
#if BOOST_VERSION >= 103500
#include <boost/system/system_error.hpp>
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "libtorrent/config.hpp"
#include "libtorrent/storage.hpp"
#include "libtorrent/torrent.hpp"
#include "libtorrent/hasher.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/peer_id.hpp"
#include "libtorrent/file.hpp"
#include "libtorrent/invariant_check.hpp"
#include "libtorrent/file_pool.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/disk_buffer_holder.hpp"
#include "libtorrent/alloca.hpp"
#include "libtorrent/allocator.hpp" // page_size

#include "../../src/twister.h"

#include <cstdio>

//#define TORRENT_PARTIAL_HASH_LOG

#if defined(__APPLE__)
// for getattrlist()
#include <sys/attr.h>
#include <unistd.h>
// for statfs()
#include <sys/param.h>
#include <sys/mount.h>
#endif

#if defined(__linux__)
#include <sys/statfs.h>
#endif

#if defined(__FreeBSD__)
// for statfs()
#include <sys/param.h>
#include <sys/mount.h>
#endif

// for convert_to_wstring and convert_to_native
#include "libtorrent/escape_string.hpp"

namespace libtorrent
{
	// matches the sizes and timestamps of the files passed in
	// in non-compact mode, actual file sizes and timestamps
	// are allowed to be bigger and more recent than the fast
	// resume data. This is because full allocation will not move
	// pieces, so any older version of the resume data will
	// still be a correct subset of the actual data on disk.
	enum flags_t
	{
		compact_mode = 1,
		ignore_timestamps = 2
	};

	void storage_interface::set_error(std::string const& file, error_code const& ec) const
	{
		m_error_file = file;
		m_error = ec;
	}

	// for backwards compatibility, let the default readv and
	// writev implementations be implemented in terms of the
	// old read and write
	int storage_interface::readv(file::iovec_t const* bufs
		, int slot, int offset, int num_bufs, int flags)
	{
		int ret = 0;
		for (file::iovec_t const* i = bufs, *end(bufs + num_bufs); i < end; ++i)
		{
			int r = read((char*)i->iov_base, slot, offset, i->iov_len);
			offset += i->iov_len;
			if (r == -1) return -1;
			ret += r;
		}
		return ret;
	}

	int storage_interface::writev(file::iovec_t const* bufs, int slot
		, int offset, int num_bufs, int flags)
	{
		int ret = 0;
		for (file::iovec_t const* i = bufs, *end(bufs + num_bufs); i < end; ++i)
		{
			int r = write((char const*)i->iov_base, slot, offset, i->iov_len);
			offset += i->iov_len;
			if (r == -1) return -1;
			ret += r;
		}
		return ret;
	}

	int copy_bufs(file::iovec_t const* bufs, int bytes, file::iovec_t* target)
	{
		int size = 0;
		int ret = 1;
		for (;;)
		{
			*target = *bufs;
			size += bufs->iov_len;
			if (size >= bytes)
			{
				target->iov_len -= size - bytes;
				return ret;
			}
			++bufs;
			++target;
			++ret;
		}
	}

	void advance_bufs(file::iovec_t*& bufs, int bytes)
	{
		int size = 0;
		for (;;)
		{
			size += bufs->iov_len;
			if (size >= bytes)
			{
				((char*&)bufs->iov_base) += bufs->iov_len - (size - bytes);
				bufs->iov_len = size - bytes;
				return;
			}
			++bufs;
		}
	}

	int bufs_size(file::iovec_t const* bufs, int num_bufs)
	{
		int size = 0;
		for (file::iovec_t const* i = bufs, *end(bufs + num_bufs); i < end; ++i)
			size += i->iov_len;
		return size;
	}
	
	void clear_bufs(file::iovec_t const* bufs, int num_bufs)
	{
		for (file::iovec_t const* i = bufs, *end(bufs + num_bufs); i < end; ++i)
			std::memset(i->iov_base, 0, i->iov_len);
	}

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
	int count_bufs(file::iovec_t const* bufs, int bytes)
	{
		int size = 0;
		int count = 1;
		if (bytes == 0) return 0;
		for (file::iovec_t const* i = bufs;; ++i, ++count)
		{
			size += i->iov_len;
			TORRENT_ASSERT(size <= bytes);
			if (size >= bytes) return count;
		}
	}
#endif

    int piece_manager::hash_for_slot(int slot, bool *hash_ok, boost::uint32_t *post_flags, int piece_size)
	{
		TORRENT_ASSERT_VAL(!error(), error());
        *hash_ok = false;

		int num_read = 0;
        int slot_size = piece_size;

        file::iovec_t buf;
        disk_buffer_holder holder(*m_storage->disk_pool()
                                  , m_storage->disk_pool()->allocate_buffer("hash temp"));
        buf.iov_base = holder.get();
        buf.iov_len = slot_size;
        // deliberately pass in 0 as flags, to disable random_access
        int ret = m_storage->readv(&buf, slot, 0, 1, 0);
        //printf("piece_manager::hash_for_slot %d ret=%d\n", slot, ret);
        if (ret > 0) num_read += ret;
        // TODO: if the read fails, set error and exit immediately

        if (ret > 0)
        {
            std::string errmsg;
            *hash_ok = acceptSignedPost((char const*)buf.iov_base, ret,
                                        m_info->name(), slot, errmsg, post_flags);
        }

        if (error()) return 0;

        return num_read;
	}

	default_storage::default_storage(file_storage const& fs, file_storage const* mapped, std::string const& path
		, CLevelDB &db, std::vector<boost::uint8_t> const& file_prio)
		: m_files(fs)
		, m_file_priority(file_prio)
		, m_db_path(path)
		, m_db(db)
		, m_page_size(page_size())
		, m_allocate_files(false)
	{
		if (mapped) m_mapped_files.reset(new file_storage(*mapped));

		TORRENT_ASSERT(m_files.begin() != m_files.end());
	}

	default_storage::~default_storage() { }

	bool default_storage::initialize(bool allocate_files)
	{
		m_allocate_files = allocate_files;
		error_code ec;

		std::vector<boost::uint8_t>().swap(m_file_priority);

		return error() ? true : false;
	}

#ifndef TORRENT_NO_DEPRECATE
	void default_storage::finalize_file(int index) {}
#endif

	bool default_storage::has_any_file()
	{
        return true;
	}

	bool default_storage::rename_file(int index, std::string const& new_filename)
	{
		return false;
	}

	bool default_storage::release_files()
	{
		return false;
	}

	void default_storage::delete_one_file(std::string const& p)
	{
		error_code ec;
		remove(p, ec);
		
		if (ec && ec != boost::system::errc::no_such_file_or_directory)
			set_error(p, ec);
	}

	bool default_storage::delete_files()
	{
		return false;
	}

	bool default_storage::write_resume_data(entry& rd) const
	{
		TORRENT_ASSERT(rd.type() == entry::dictionary_t);
		return false;
	}

	int default_storage::sparse_end(int slot) const
	{
		TORRENT_ASSERT(slot >= 0);
		TORRENT_ASSERT(slot < m_files.num_pieces());

        return slot;
	}

	bool default_storage::verify_resume_data(lazy_entry const& rd, error_code& error)
	{
		lazy_entry const* file_priority = rd.dict_find_list("file_priority");
		if (file_priority && file_priority->list_size()
			== files().num_files())
		{
			m_file_priority.resize(file_priority->list_size());
			for (int i = 0; i < file_priority->list_size(); ++i)
				m_file_priority[i] = boost::uint8_t(file_priority->list_int_value_at(i, 1));
		}


		bool seed = false;
		
        if (lazy_entry const* pieces = rd.dict_find_string("pieces"))
		{
			if (int(pieces->string_length()) == m_files.num_pieces())
			{
				seed = true;
				char const* p = pieces->string_ptr();
				for (int i = 0; i < pieces->string_length(); ++i)
				{
					if ((p[i] & 1) == 1) continue;
					seed = false;
					break;
				}
			}
		}
		else
		{
			error = errors::missing_pieces;
			return false;
		}

        int flags = (settings().ignore_resume_timestamps ? ignore_timestamps : 0);

        return true;

	}

	// returns true on success
	int default_storage::move_storage(std::string const& sp, int flags)
	{
		int ret = piece_manager::no_error;
		return ret;
	}


#define TORRENT_ALLOCATE_BLOCKS(bufs, num_blocks, piece_size) \
	int num_blocks = (piece_size + disk_pool()->block_size() - 1) / disk_pool()->block_size(); \
	file::iovec_t* bufs = TORRENT_ALLOCA(file::iovec_t, num_blocks); \
	for (int i = 0, size = piece_size; i < num_blocks; ++i) \
	{ \
		bufs[i].iov_base = disk_pool()->allocate_buffer("move temp"); \
		bufs[i].iov_len = (std::min)(disk_pool()->block_size(), size); \
		size -= bufs[i].iov_len; \
	}

#define TORRENT_FREE_BLOCKS(bufs, num_blocks) \
	for (int i = 0; i < num_blocks; ++i) \
		disk_pool()->free_buffer((char*)bufs[i].iov_base);

#define TORRENT_SET_SIZE(bufs, size, num_bufs) \
	for (num_bufs = 0; size > 0; size -= disk_pool()->block_size(), ++num_bufs) \
		bufs[num_bufs].iov_len = (std::min)(disk_pool()->block_size(), size)
	

	bool default_storage::move_slot(int src_slot, int dst_slot)
	{
        return false;
	}

	bool default_storage::swap_slots(int slot1, int slot2)
	{
        return false;
	}

	bool default_storage::swap_slots3(int slot1, int slot2, int slot3)
	{
        return false;
	}

	int default_storage::writev(file::iovec_t const* bufs, int slot, int offset
		, int num_bufs, int flags)
	{
        TORRENT_ASSERT(bufs != 0);
        TORRENT_ASSERT(slot >= 0);
        TORRENT_ASSERT(slot < m_files.num_pieces());
        TORRENT_ASSERT(num_bufs == 1);
        TORRENT_ASSERT(offset == 0);

        std::string postStr(static_cast<char *>(bufs[0].iov_base), bufs[0].iov_len);

        int tries = 2;
        while( tries-- ) {
            try {
                std::pair<std::string, int> pathSlot = std::make_pair(m_db_path, slot);
                if( m_db.Write(std::make_pair('p', pathSlot), postStr) ) {
                    return postStr.size();
                } else {
                    return -1;
                }
            } catch( leveldb_error &e ) {
                m_db.RepairDB();
            }
        }
        return -1;
	}

	size_type default_storage::physical_offset(int slot, int offset)
	{
		TORRENT_ASSERT(slot >= 0);
		TORRENT_ASSERT(slot < m_files.num_pieces());
		TORRENT_ASSERT(offset >= 0);

        // this means we don't support true physical offset
        // just make something up
        return size_type(slot) * files().piece_length() + offset;
	}

	void default_storage::hint_read(int slot, int offset, int size)
	{
	}

	int default_storage::readv(file::iovec_t const* bufs, int slot, int offset
		, int num_bufs, int flags)
	{
        TORRENT_ASSERT(bufs != 0);
        TORRENT_ASSERT(slot >= 0);
        TORRENT_ASSERT(slot < m_files.num_pieces());
        TORRENT_ASSERT(num_bufs == 1);
        TORRENT_ASSERT(offset == 0);

        int tries = 2;
        while( tries-- ) {
            try {
                std::string postStr;
                std::pair<std::string, int> pathSlot = std::make_pair(m_db_path, slot);
                if( m_db.Read(std::make_pair('p', pathSlot), postStr) ) {
                    TORRENT_ASSERT(bufs[0].iov_len >= postStr.size());
                    memcpy(bufs[0].iov_base, postStr.data(), postStr.size());
                    return postStr.size();
                } else {
                    return 0;
                }
            } catch( leveldb_error &e ) {
                m_db.RepairDB();
            }
        }
        return -1;
	}

	int default_storage::write(
		const char* buf
		, int slot
		, int offset
		, int size)
	{
		file::iovec_t b = { (file::iovec_base_t)buf, size_t(size) };
		return writev(&b, slot, offset, 1, 0);
	}

	int default_storage::read(
		char* buf
		, int slot
		, int offset
		, int size)
	{
		file::iovec_t b = { (file::iovec_base_t)buf, size_t(size) };
		return readv(&b, slot, offset, 1);
	}

	boost::intrusive_ptr<file> default_storage::open_file(file_storage::iterator fe, int mode
		, error_code& ec) const
	{
		return new file();
	}

	storage_interface* default_storage_constructor(file_storage const& fs
		, file_storage const* mapped, std::string const& path, CLevelDB &db
		, std::vector<boost::uint8_t> const& file_prio)
	{
		return new default_storage(fs, mapped, path, db, file_prio);
	}

	int disabled_storage::readv(file::iovec_t const* bufs, int slot, int offset, int num_bufs, int flags)
	{
#ifdef TORRENT_DISK_STATS
		disk_buffer_pool* pool = disk_pool();
		if (pool)
		{
			pool->m_disk_access_log << log_time() << " read "
				<< physical_offset(slot, offset) << std::endl;
		}
#endif
		int ret = 0;
		for (int i = 0; i < num_bufs; ++i)
			ret += bufs[i].iov_len;
#ifdef TORRENT_DISK_STATS
		if (pool)
		{
			pool->m_disk_access_log << log_time() << " read_end "
				<< (physical_offset(slot, offset) + ret) << std::endl;
		}
#endif
		return ret;
	}

	int disabled_storage::writev(file::iovec_t const* bufs, int slot, int offset, int num_bufs, int flags)
	{
#ifdef TORRENT_DISK_STATS
		disk_buffer_pool* pool = disk_pool();
		if (pool)
		{
			pool->m_disk_access_log << log_time() << " write "
				<< physical_offset(slot, offset) << std::endl;
		}
#endif
		int ret = 0;
		for (int i = 0; i < num_bufs; ++i)
			ret += bufs[i].iov_len;
#ifdef TORRENT_DISK_STATS
		if (pool)
		{
			pool->m_disk_access_log << log_time() << " write_end "
				<< (physical_offset(slot, offset) + ret) << std::endl;
		}
#endif
		return ret;
	}

	storage_interface* disabled_storage_constructor(file_storage const& fs
		, file_storage const* mapped, std::string const& path, file_pool& fp
		, std::vector<boost::uint8_t> const&)
	{
		return new disabled_storage(fs.piece_length());
	}

	// -- piece_manager -----------------------------------------------------

	piece_manager::piece_manager(
		boost::shared_ptr<void> const& torrent
		, boost::intrusive_ptr<torrent_info const> info
		, std::string const& save_path
		, CLevelDB &db
		, disk_io_thread& io
		, storage_constructor_type sc
		, storage_mode_t sm
		, std::vector<boost::uint8_t> const& file_prio)
		: m_info(info)
		, m_files(m_info->files())
		, m_storage(sc(m_info->orig_files(), &m_info->files() != &m_info->orig_files()
	    ? &m_info->files() : 0, to_hex(m_info->info_hash().to_string()), db, file_prio))
		, m_storage_mode(sm)
		, m_save_path(complete(save_path))
		, m_state(state_none)
		, m_current_slot(0)
		, m_out_of_place(false)
		, m_scratch_piece(-1)
		, m_last_piece(-1)
		, m_storage_constructor(sc)
		, m_io_thread(io)
		, m_torrent(torrent)
	{
		m_storage->m_disk_pool = &m_io_thread;
	}

	piece_manager::~piece_manager()
	{
	}

	void piece_manager::async_save_resume_data(
		boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::save_resume_data;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_clear_read_cache(
		boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::clear_read_cache;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_release_files(
		boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::release_files;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::abort_disk_io()
	{
		m_io_thread.stop(this);
	}

	void piece_manager::async_delete_files(
		boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::delete_files;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_move_storage(std::string const& p, int flags
		, boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::move_storage;
		j.str = p;
		j.piece = flags;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_check_fastresume(lazy_entry const* resume_data
		, boost::function<void(int, disk_io_job const&)> const& handler)
	{
		TORRENT_ASSERT(resume_data != 0);
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::check_fastresume;
		j.buffer = (char*)resume_data;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_rename_file(int index, std::string const& name
		, boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.piece = index;
		j.str = name;
		j.action = disk_io_job::rename_file;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_check_files(
		boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::check_files;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_read_and_hash(
		peer_request const& r
		, boost::function<void(int, disk_io_job const&)> const& handler
		, int cache_expiry)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::read_and_hash;
		j.piece = r.piece;
		j.offset = r.start;
		j.buffer_size = r.length;
		j.buffer = 0;
		j.cache_min_time = cache_expiry;
		TORRENT_ASSERT(r.length <= 16 * 1024);
		m_io_thread.add_job(j, handler);
#ifdef TORRENT_DEBUG
		mutex::scoped_lock l(m_mutex);
		// if this assert is hit, it suggests
		// that check_files was not successful
		TORRENT_ASSERT(slot_for(r.piece) >= 0);
#endif
	}

	void piece_manager::async_cache(int piece
		, boost::function<void(int, disk_io_job const&)> const& handler
		, int cache_expiry)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::cache_piece;
		j.piece = piece;
		j.offset = 0;
		j.buffer_size = 0;
		j.buffer = 0;
		j.cache_min_time = cache_expiry;
		m_io_thread.add_job(j, handler);
	}

	void piece_manager::async_read(
		peer_request const& r
		, boost::function<void(int, disk_io_job const&)> const& handler
		, int cache_line_size
		, int cache_expiry)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::read;
		j.piece = r.piece;
		j.offset = r.start;
		j.buffer_size = r.length;
		j.buffer = 0;
		j.max_cache_line = cache_line_size;
		j.cache_min_time = cache_expiry;

		// if a buffer is not specified, only one block can be read
		// since that is the size of the pool allocator's buffers
		TORRENT_ASSERT(r.length <= 16 * 1024);
		m_io_thread.add_job(j, handler);
#ifdef TORRENT_DEBUG
		mutex::scoped_lock l(m_mutex);
		// if this assert is hit, it suggests
		// that check_files was not successful
		TORRENT_ASSERT(slot_for(r.piece) >= 0);
#endif
	}

	int piece_manager::async_write(
		peer_request const& r
		, disk_buffer_holder& buffer
		, boost::function<void(int, disk_io_job const&)> const& handler)
	{
		//printf("async_write: piece %d size %d\n", r.piece, r.length );
		TORRENT_ASSERT(r.length <= 16 * 1024);
		// the buffer needs to be allocated through the io_thread
		TORRENT_ASSERT(m_io_thread.is_disk_buffer(buffer.get()));

		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::write;
		j.piece = r.piece;
		j.offset = r.start;
		j.buffer_size = r.length;
		j.buffer = buffer.get();
		int queue_size = m_io_thread.add_job(j, handler);
		buffer.release();

		return queue_size;
	}

	void piece_manager::async_hash(int piece
		, boost::function<void(int, disk_io_job const&)> const& handler)
	{
		disk_io_job j;
		j.storage = this;
		j.action = disk_io_job::hash;
		j.piece = piece;

		m_io_thread.add_job(j, handler);
	}

	std::string piece_manager::save_path() const
	{
		mutex::scoped_lock l(m_mutex);
		return m_save_path;
	}

	bool piece_manager::hash_for_piece_impl(int piece, int* readback, boost::uint32_t *post_flags)
	{
		TORRENT_ASSERT(!m_storage->error());

		bool hash_ok = false;

		int slot = slot_for(piece);
		int read = hash_for_slot(slot, &hash_ok, post_flags, m_files.piece_size(piece));
		if (readback) *readback = read;
		if (m_storage->error()) return false;
		return hash_ok;
	}

	int piece_manager::move_storage_impl(std::string const& save_path, int flags)
	{
		int ret = m_storage->move_storage(save_path, flags);

		if (ret == no_error || ret == need_full_check)
		{
			m_save_path = complete(save_path);
		}
		return ret;
	}

	void piece_manager::write_resume_data(entry& rd) const
	{
		mutex::scoped_lock lock(m_mutex);

		INVARIANT_CHECK;

		m_storage->write_resume_data(rd);

        rd["allocation"] = m_storage_mode == storage_mode_sparse?"sparse"
			:m_storage_mode == storage_mode_allocate?"full":"compact";
	}

	void piece_manager::mark_failed(int piece_index)
	{
        return;
	}

	void piece_manager::hint_read_impl(int piece_index, int offset, int size)
	{
		m_last_piece = piece_index;
		int slot = slot_for(piece_index);
		if (slot <= 0) return;
		m_storage->hint_read(slot, offset, size);
	}

	int piece_manager::read_impl(
		file::iovec_t* bufs
		, int piece_index
		, int offset
		, int num_bufs)
	{
		TORRENT_ASSERT(bufs);
		TORRENT_ASSERT(offset >= 0);
		TORRENT_ASSERT(num_bufs > 0);
		m_last_piece = piece_index;
		int slot = slot_for(piece_index);
		return m_storage->readv(bufs, slot, offset, num_bufs);
	}

	int piece_manager::write_impl(
		file::iovec_t* bufs
	  , int piece_index
	  , int offset
	  , int num_bufs)
	{
		TORRENT_ASSERT(bufs);
		TORRENT_ASSERT(offset >= 0);
		TORRENT_ASSERT(num_bufs > 0);
		TORRENT_ASSERT(piece_index >= 0 && piece_index < m_files.num_pieces());

		int size = bufs_size(bufs, num_bufs);

		file::iovec_t* iov = TORRENT_ALLOCA(file::iovec_t, num_bufs);
		std::copy(bufs, bufs + num_bufs, iov);
		m_last_piece = piece_index;
		int slot = allocate_slot_for_piece(piece_index);
		int ret = m_storage->writev(bufs, slot, offset, num_bufs);
		// only save the partial hash if the write succeeds
		if (ret != size) return ret;

		if (m_storage->settings().disable_hash_checks) return ret;
		
		return ret;
	}

	size_type piece_manager::physical_offset(
		int piece_index
		, int offset)
	{
		TORRENT_ASSERT(offset >= 0);
		TORRENT_ASSERT(piece_index >= 0 && piece_index < m_files.num_pieces());

		int slot = slot_for(piece_index);
		// we may not have a slot for this piece yet.
		// assume there is no re-mapping of slots
		if (slot < 0) slot = piece_index;
        return m_storage->physical_offset(slot, offset);
	}

	int piece_manager::check_no_fastresume(error_code& error)
	{
		bool has_files = false;
		if (!m_storage->settings().no_recheck_incomplete_resume)
		{
			has_files = m_storage->has_any_file();
			if (m_storage->error())
				return fatal_disk_error;

			if (has_files)
			{
				m_state = state_full_check;
				return need_full_check;
			}
		}

		return check_init_storage(error);
	}
	
	int piece_manager::check_init_storage(error_code& error)
	{
		if (m_storage->initialize(m_storage_mode == storage_mode_allocate))
		{
			error = m_storage->error();
			TORRENT_ASSERT(error);
			m_current_slot = 0;
			return fatal_disk_error;
		}
		m_state = state_finished;
		m_scratch_buffer.reset();
		m_scratch_buffer2.reset();
		return no_error;
	}

	// check if the fastresume data is up to date
	// if it is, use it and return true. If it 
	// isn't return false and the full check
	// will be run
	int piece_manager::check_fastresume(
		lazy_entry const& rd, error_code& error)
	{
		mutex::scoped_lock lock(m_mutex);

		INVARIANT_CHECK;

		TORRENT_ASSERT(m_files.piece_length() > 0);
		
		m_current_slot = 0;

		// if we don't have any resume data, return
		if (rd.type() == lazy_entry::none_t) return check_no_fastresume(error);

		if (rd.type() != lazy_entry::dict_t)
		{
			error = errors::not_a_dictionary;
			return check_no_fastresume(error);
		}

		int block_size = (std::min)(16 * 1024, m_files.piece_length());
		int blocks_per_piece = int(rd.dict_find_int_value("blocks per piece", -1));
		if (blocks_per_piece != -1
			&& blocks_per_piece != m_files.piece_length() / block_size)
		{
			error = errors::invalid_blocks_per_piece;
			return check_no_fastresume(error);
		}

		if (!m_storage->verify_resume_data(rd, error))
			return check_no_fastresume(error);

		return check_init_storage(error);
	}

/*
   state chart:

   check_fastresume()  ----------+
                                 |
      |        |                 |
      |        v                 v
      |  +------------+   +---------------+
      |  | full_check |-->| expand_pieses |
      |  +------------+   +---------------+
      |        |                 |
      |        v                 |
      |  +--------------+        |
      +->|   finished   | <------+
         +--------------+
*/


	// performs the full check and full allocation
	// (if necessary). returns true if finished and
	// false if it should be called again
	// the second return value is the progress the
	// file check is at. 0 is nothing done, and 1
	// is finished
	int piece_manager::check_files(int& current_slot, int& have_piece, error_code& error, boost::uint32_t *post_flags)
	{
		if (m_state == state_none) return check_no_fastresume(error);

		current_slot = m_current_slot;
		have_piece = -1;

		TORRENT_ASSERT(m_state == state_full_check);
		if (m_state == state_finished) return 0;

		int skip = check_one_piece(have_piece, post_flags);
		TORRENT_ASSERT(m_current_slot <= m_files.num_pieces());

		if (skip == -1)
		{
			error = m_storage->error();
			TORRENT_ASSERT(error);
			return fatal_disk_error;
		}

		if (skip > 0)
		{
			clear_error();
			// skip means that the piece we checked failed to be read from disk
			// completely. This may be caused by the file not being there, or the
			// piece overlapping with a sparse region. We should skip 'skip' number
			// of pieces

			// current slot will increase by one below
			m_current_slot += skip - 1;
			TORRENT_ASSERT(m_current_slot <= m_files.num_pieces());
		}

		++m_current_slot;
		current_slot = m_current_slot;

		if (m_current_slot >= m_files.num_pieces())
		{
			TORRENT_ASSERT(m_current_slot == m_files.num_pieces());

			return check_init_storage(error);
		}

		return need_full_check;
	}

	// -1 = error, 0 = ok, >0 = skip this many pieces
	int piece_manager::check_one_piece(int& have_piece, boost::uint32_t *post_flags)
	{
		// ------------------------
		//    DO THE FULL CHECK
		// ------------------------

		TORRENT_ASSERT(have_piece == -1);

		// initialization for the full check

		bool hash_ok = false;
		int num_read = 0;
		int piece_size = m_files.piece_size(m_current_slot);

		num_read = hash_for_slot(m_current_slot, &hash_ok, post_flags, piece_size);

		if (!hash_ok)
		{
			// the data did not match any piece. Maybe we're reading
			// from a sparse region, see if we are and skip
			if (m_current_slot == m_files.num_pieces() -1) return 0;

            //int next_slot = m_storage->sparse_end(m_current_slot + 1);
            int next_slot = m_current_slot + 1;
                        if (next_slot > m_current_slot + 1) return next_slot - m_current_slot;
		}

		return 0;
	}

	void piece_manager::switch_to_full_mode()
	{
		m_storage_mode = storage_mode_sparse;
	}

	int piece_manager::allocate_slot_for_piece(int piece_index)
	{
        return piece_index;
	}

	bool piece_manager::allocate_slots_impl(int num_slots, mutex::scoped_lock& l
		, bool abort_on_disk)
	{
        TORRENT_ASSERT(false);
        return 0;
	}

	int piece_manager::slot_for(int piece) const
	{
        return piece;
	}

	int piece_manager::piece_for(int slot) const
	{
        return slot;
	}
		
#if defined TORRENT_DEBUG && !defined TORRENT_DISABLE_INVARIANT_CHECKS
	void piece_manager::check_invariant() const
	{
		TORRENT_ASSERT(m_current_slot <= m_files.num_pieces());
	}

#endif
} // namespace libtorrent

