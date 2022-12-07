#pragma once
#include <concepts>
#include <stdio.h> // for FILE
#include <openssl/evp.h> // EVP_MD_CTX

namespace jks
{
namespace util
{

// RAII wrapper for handles
template <typename T> concept Handle = std::is_pointer_v<T>;
template <class...> constexpr bool always_false = false; // for static assert
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
using EvpHandle = SafeHandle<EVP_MD_CTX *>;

}
}