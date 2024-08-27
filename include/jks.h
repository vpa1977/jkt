#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace jks
{

constexpr uint32_t MAGIC = 0xfeedfeed;
constexpr auto DEFAULT_CERTIFICATE_TYPE = u"X.509";

class NotJKSStore final : public std::runtime_error {
    public:
	NotJKSStore()
		: std::runtime_error("not jks store")
	{
	}
};

class JKSStore final {
    public:
	JKSStore(const std::u16string &password)
		: m_password(password){};
	void EmplaceTrustedCertificate(const std::u16string &alias,
				       std::vector<uint8_t> &data);

	std::vector<uint8_t>
	GetTrustedCertificate(const std::u16string &alias) const
	{
		auto where = m_certificates.find(alias);
		if (where == m_certificates.end())
			throw std::runtime_error("unable to find alias");
		return where->second.m_certificate.m_data;
	}

    private:
	friend std::istream &operator>>(std::istream &is, JKSStore &store);
	friend std::ostream &operator<<(std::ostream &is,
					const JKSStore &store);

	using CertificateData = std::vector<uint8_t>;

	struct Certificate final {
		Certificate()
			: m_type(DEFAULT_CERTIFICATE_TYPE)
		{
		}
		Certificate(const std::u16string &type,
			    const CertificateData &data)
			: m_type(type)
			, m_data(data)
		{
		}
		std::u16string m_type;
		CertificateData m_data;
	};

	struct KeyEntry final {
		void Read(std::istream &, uint32_t version);
		void Write(std::ostream &, uint32_t version) const;

		std::u16string m_alias;
		uint64_t m_timestampMs;
		std::vector<uint8_t> m_encryptedKey;
		std::vector<Certificate> m_certificateChain;
	};
	struct TrustedCertificate final {
		void Read(std::istream &, uint32_t version);
		void Write(std::ostream &, uint32_t version) const;

		std::u16string m_alias;
		uint64_t m_timestampMs;
		Certificate m_certificate;
	};

	std::unordered_map<std::u16string, KeyEntry> m_keys;
	std::unordered_map<std::u16string, TrustedCertificate> m_certificates;
	std::u16string m_password;
	uint32_t m_version;
};

std::istream &operator>>(std::istream &is, JKSStore &store);

std::ostream &operator<<(std::ostream &is, const JKSStore &store);

}
