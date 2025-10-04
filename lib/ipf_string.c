/*
  ipf_string.c -- string handling (with encoding)
  Copyright (C) 2012-2024 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <info@libzip.org>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "zipint.h"

static void
update_keys(zip_pkware_keys_t *keys, zip_uint8_t b) {
    keys->key[0] = (zip_uint32_t)crc32(keys->key[0] ^ 0xffffffffUL, &b, 1) ^ 0xffffffffUL;
    keys->key[1] = (keys->key[1] + (keys->key[0] & 0xff)) * 134775813 + 1;
    b = (zip_uint8_t)(keys->key[1] >> 24);
    keys->key[2] = (zip_uint32_t)crc32(keys->key[2] ^ 0xffffffffUL, &b, 1) ^ 0xffffffffUL;
}


ZIP_EXTERN const char *
ipf_get_name(zip_t *za, zip_uint64_t idx, zip_flags_t flags) {
    return _ipf_get_name(za, idx, flags, &za->error);
}


const char *
_ipf_get_name(zip_t *za, zip_uint64_t idx, zip_flags_t flags, zip_error_t *error) {
    zip_dirent_t *de;
    const zip_uint8_t *str;

    if ((de = _zip_get_dirent(za, idx, flags, error)) == NULL)
        return NULL;

    if ((str = _ipf_string_get(de->filename, NULL, flags, error, za->default_password)) == NULL)
        return NULL;

    return (const char *)str;
}


const zip_uint8_t *
_ipf_string_get(zip_string_t *string, zip_uint32_t *lenp, zip_flags_t flags, zip_error_t *error, const char *password) {
    static const zip_uint8_t empty[1] = "";
    zip_pkware_keys_t keys;
    size_t password_len, i;

    if (string == NULL) {
        if (lenp)
            *lenp = 0;
        return empty;
    }

    if (password == NULL)
        return _zip_string_get(string, lenp, flags, error);

    /* decrypt first */
    _zip_pkware_keys_reset(&keys);
    password_len = strlen(password);
    for (i = 0; i < password_len; ++i) {
        update_keys(&keys, password[i]);
    }
    _zip_pkware_decrypt(&keys, string->raw, string->raw, string->length);

    if ((flags & ZIP_FL_ENC_RAW) == 0) {
        /* start guessing */
        if (string->encoding == ZIP_ENCODING_UNKNOWN) {
            /* guess encoding, sets string->encoding */
            (void)_zip_guess_encoding(string, ZIP_ENCODING_UNKNOWN);
        }

        if (((flags & ZIP_FL_ENC_STRICT) && string->encoding != ZIP_ENCODING_ASCII && string->encoding != ZIP_ENCODING_UTF8_KNOWN) || (string->encoding == ZIP_ENCODING_CP437)) {
            if (string->converted == NULL) {
                if ((string->converted = _zip_cp437_to_utf8(string->raw, string->length, &string->converted_length, error)) == NULL)
                    return NULL;
            }
            if (lenp)
                *lenp = string->converted_length;
            return string->converted;
        }
    }

    if (lenp)
        *lenp = string->length;
    return string->raw;
}
