#pragma once

#include <vector>
#include <string>
#include <unordered_map>

namespace jks
{

constexpr uint32_t MAGIC = 0xfeedfeed;

class JKSStore final {
    public:
	JKSStore(const std::u16string &password)
		: m_password(password){};
	void Load();
	void Save();

    private:
	friend std::istream &operator>>(std::istream &is, JKSStore &store);
	friend std::ostream &operator<<(std::ostream &is,
					const JKSStore &store);

	using CertificateData = std::vector<uint8_t>;

	struct Certificate final {
		std::u16string m_type;
		CertificateData m_data;
	};

	struct KeyEntry final {
		void Read(std::istream &, uint32_t version);
		void Write(std::ostream &, uint32_t version);

		std::u16string m_alias;
		uint64_t m_timestampMs;
		std::vector<uint8_t> m_encryptedKey;
		std::vector<Certificate> m_certificateChain;
	};
	struct TrustedCertificate final {
		void Read(std::istream &, uint32_t version);
		void Write(std::ostream &, uint32_t version);

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
