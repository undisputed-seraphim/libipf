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


/* Does this string already look like a regular (plaintext) name?
   Encrypted (IPF) names are arbitrary bytes, so they normally fail this check. */
static bool
ipf_name_is_plaintext(zip_string_t *string) {
    zip_string_t view;

    view.raw = string->raw;
    view.length = string->length;
    view.encoding = ZIP_ENCODING_UNKNOWN;
    view.converted = NULL;
    view.converted_length = 0;

    return _zip_guess_encoding(&view, ZIP_ENCODING_UTF8_KNOWN) != ZIP_ENCODING_ERROR;
}


const zip_uint8_t *
_ipf_string_get(zip_string_t *string, zip_uint32_t *lenp, zip_flags_t flags, zip_error_t *error, const char *password) {
    static const zip_uint8_t empty[1] = "";
    zip_pkware_keys_t keys;
    zip_string_t plain;
    const zip_uint8_t *result;
    zip_uint8_t *decrypted, *cached;
    zip_uint32_t result_length;
    size_t password_len, i;

    if (string == NULL) {
        if (lenp)
            *lenp = 0;
        return empty;
    }

    if (password == NULL)
        return _zip_string_get(string, lenp, flags, error);

    /* Regular archives opened with a default password for their content still
       have plaintext names; only decrypt names that are not already valid text. */
    if (ipf_name_is_plaintext(string))
        return _zip_string_get(string, lenp, flags, error);

    /* reuse the cached plaintext if it was produced with the same password */
    if (string->decrypted != NULL && string->decryption_password != NULL && strcmp(string->decryption_password, password) == 0) {
        if (lenp)
            *lenp = string->decrypted_length;
        return string->decrypted;
    }

    /* decrypt into a scratch buffer so the original ciphertext is preserved */
    if ((decrypted = (zip_uint8_t *)malloc((size_t)string->length + 1)) == NULL) {
        zip_error_set(error, ZIP_ER_MEMORY, 0);
        return NULL;
    }

    _zip_pkware_keys_reset(&keys);
    password_len = strlen(password);
    for (i = 0; i < password_len; ++i) {
        update_keys(&keys, (zip_uint8_t)password[i]);
    }
    _zip_pkware_decrypt(&keys, decrypted, string->raw, string->length);
    decrypted[string->length] = '\0';

    plain.raw = decrypted;
    plain.length = string->length;
    plain.encoding = ZIP_ENCODING_UNKNOWN;
    plain.converted = NULL;
    plain.converted_length = 0;

    /* only accept the result if it decrypted to a valid name, otherwise leave it alone */
    if (_zip_guess_encoding(&plain, ZIP_ENCODING_UTF8_KNOWN) == ZIP_ENCODING_ERROR) {
        free(decrypted);
        return _zip_string_get(string, lenp, flags, error);
    }

    result = _zip_string_get(&plain, &result_length, flags, error);
    if (result == NULL) {
        free(decrypted);
        free(plain.converted);
        return NULL;
    }

    if ((cached = (zip_uint8_t *)malloc((size_t)result_length + 1)) == NULL) {
        free(decrypted);
        free(plain.converted);
        zip_error_set(error, ZIP_ER_MEMORY, 0);
        return NULL;
    }
    (void)memcpy_s(cached, (size_t)result_length + 1, result, result_length);
    cached[result_length] = '\0';

    free(decrypted);
    free(plain.converted);

    free(string->decrypted);
    if (string->decryption_password != NULL) {
        _zip_crypto_clear(string->decryption_password, strlen(string->decryption_password));
        free(string->decryption_password);
    }
    string->decrypted = cached;
    string->decrypted_length = result_length;
    string->decryption_password = strdup(password);

    if (lenp)
        *lenp = string->decrypted_length;
    return string->decrypted;
}
