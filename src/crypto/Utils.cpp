#include <iomanip>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>

namespace CloudPrivacy {
namespace Utils {

std::string Base64Encode(const std::string &input) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // no newlines
  BIO_write(bio, input.data(), input.length());
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);

  std::string result(bufferPtr->data, bufferPtr->length);
  BIO_free_all(bio);

  return result;
}

std::string Base64Decode(const std::string &input) {
  BIO *bio, *b64;
  int decodeLen = input.length(); // estimate
  char *buffer = new char[decodeLen];

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input.data(), input.length());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  int len = BIO_read(bio, buffer, input.length());

  std::string result(buffer, len);
  delete[] buffer;
  BIO_free_all(bio);

  return result;
}

std::string HexEncode(const unsigned char *data, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << (int)data[i];
  }
  return ss.str();
}

} 
} 
