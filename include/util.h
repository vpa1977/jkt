#pragma once
#include <concepts>
#include <span>
#include <vector>
#include <string>

namespace jks
{
namespace util
{
// password and digest functions
std::vector<uint8_t> create_digest(std::span<uint8_t> data,
				   const char *password);
std::vector<uint8_t> convert_to_bytes(const char *data);

// read/write utilities for aliases
std::wstring read_utf(std::span<uint8_t> data);
std::vector<uint8_t> write_utf(std::wstring &data);

// RAII wrapper for handles
template <typename T> concept Handle = std::is_pointer_v<T>;
template <Handle T> struct SafeHandle final {
	explicit SafeHandle(T handle)
		: m_handle(handle)
	{
	}
	SafeHandle(const SafeHandle<T> &) = delete;
	SafeHandle(SafeHandle<T> &&handle) noexcept
	{
		this->operator=(handle);
	}

	T &operator=(const SafeHandle<T> &other) = delete;
	T &operator=(SafeHandle<T> &&other) noexcept
	{
		m_handle = other.m_handle;
		other.m_handle = nullptr;
	}

	~SafeHandle()
	{
		release(m_handle);
		m_handle = nullptr;
	}

	operator T() noexcept
	{
		return m_handle;
	}

	void release(T t);

	T m_handle;
};

using FileHandle = SafeHandle<FILE *>;

}
}