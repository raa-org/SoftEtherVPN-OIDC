// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcUrlEncoding.c
// URL percent-encoding/decoding (RFC 3986) for OIDC query/form params.

#include <string.h>
#include "OidcUrlEncoding.h"

int OidcUrlEncode(const char* s, char* out, size_t outsz)
{
	size_t i;
	size_t j;
	static const char hex[] = "0123456789ABCDEF";

	if (!s || !out || outsz == 0)
	{
		return 0;
	}

	i = 0;
	j = 0;
	while (s[i] != '\0')
	{
		unsigned char c;

		if (j + 1 >= outsz)
		{
			return 0;
		}

		c = (unsigned char)s[i];

		if ((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~')
		{
			out[j] = (char)c;
			j++;
		}
		else
		{
			if (j + 3 >= outsz)
			{
				return 0;
			}
			out[j] = '%';
			out[j + 1] = hex[(c >> 4) & 0x0F];
			out[j + 2] = hex[c & 0x0F];
			j += 3;
		}

		i++;
	}

	if (j >= outsz)
	{
		return 0;
	}

	out[j] = '\0';
	return 1;
}

int OidcUrlDecode(const char* s, char* out, size_t outsz)
{
	size_t i;
	size_t j;

	if (!s || !out || outsz == 0)
	{
		return 0;
	}

	i = 0;
	j = 0;
	while (s[i] != '\0')
	{
		unsigned char c;

		if (j + 1 >= outsz)
		{
			return 0;
		}

		if (s[i] == '%' && s[i + 1] && s[i + 2])
		{
			int hi;
			int lo;

			hi = s[i + 1];
			lo = s[i + 2];

			if (hi >= '0' && hi <= '9') { hi -= '0'; }
			else if (hi >= 'A' && hi <= 'F') { hi = hi - 'A' + 10; }
			else if (hi >= 'a' && hi <= 'f') { hi = hi - 'a' + 10; }
			else { return 0; }

			if (lo >= '0' && lo <= '9') { lo -= '0'; }
			else if (lo >= 'A' && lo <= 'F') { lo = lo - 'A' + 10; }
			else if (lo >= 'a' && lo <= 'f') { lo = lo - 'a' + 10; }
			else { return 0; }

			c = (unsigned char)((hi << 4) | lo);
			out[j] = (char)c;
			j++;
			i += 3;
			continue;
		}

		if (s[i] == '+')
		{
			out[j] = ' ';
			j++;
			i++;
			continue;
		}

		out[j] = s[i];
		j++;
		i++;
	}

	out[j] = '\0';
	return 1;
}
