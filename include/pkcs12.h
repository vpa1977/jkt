#pragma once

#include <string>
#include <vector>

class PCKS12Store final {
    public:
	PCKS12Store(const std::u16string &password)
		: m_password(password){};

	void EmplaceTrustedCertificate(const std::u16string &alias,
				       std::vector<uint8_t> &data);

    private:
	std::u16string m_password;
};