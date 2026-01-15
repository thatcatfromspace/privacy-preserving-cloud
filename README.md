# Data Privacy Package

This is a simple implementation of a privacy-preserving Cloud Storage Service using a Group Signature (GS) scheme that takes inspiration from the uploaded paper titled "Privacy-preserving security solution for cloud services" by L. Malina et al.

The implementation is a simple HTTP server that provides a REST API for file upload and download, and user revocation.

The current implementation takes several assumptions and simplifications to make the implementation simple and easy to understand. These assumptions are:

- RSA is used to generate group signatures and SHA is used verify signatures.
- The group manager is the only one who can revoke users.


## Features

- Group Signature (GS) for user authentication
- File upload and download
- User revocation

## Usage

### Prerequisites

- C++17
- OpenSSL
- CMake

### Building

```bash
mkdir build
cd build

# Release build
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Debug build
# cmake .. -DCMAKE_BUILD_TYPE=Debug
# make
```

### Running

```bash
# Start RM
./build/rm_service > rm.log 2>&1 &
RM_PID=$!
sleep 2

# Start CSP
./build/csp_service > csp.log 2>&1 &
CSP_PID=$!
sleep 2

# user Join
MEMBER_KEY=$(curl -s -X POST http://localhost:8081/join -d "demo_user")
ID=$(echo "$MEMBER_KEY" | head -n 1)
CERT=$(echo "$MEMBER_KEY" | tail -n 1)

echo "Got Key for ID: $ID"
echo "Certificate (len): ${#CERT}"

if [ -z "$CERT" ]; then
    echo "Failed to get certificate"
    kill $RM_PID $CSP_PID
    exit 1
fi

# construct signature (ID:Certificate)
# In real group sig, this construction would involve signing the message.
# Here we use the ID:Cert as the token.
SIG="$ID:$CERT"

# user Upload
echo "--- 2. Uploading file ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/upload \
     -H "X-Group-Sig: $SIG" \
     -d "This is a secret file content.")

echo "Upload Status: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then
    echo "Upload Failed"
    cat csp.log
    kill $RM_PID $CSP_PID
    exit 1
fi

# verify file content - rudimentary
echo "--- 3. Checking file on disk ---"
CONTENT=$(cat storage/$ID/uploaded_file.txt)
echo "File Content: $CONTENT"

if [ "$CONTENT" != "This is a secret file content." ]; then
    echo "Content Mismatch!"
    kill $RM_PID $CSP_PID
    exit 1
fi

# revoke malicious user
echo "--- 4. Revoking User ---"
curl -s -X POST http://localhost:8081/revoke -d "$ID"
echo "User Revoked."

# uploads from a malicious user fails
echo "--- 5. Uploading after revocation ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/upload \
     -H "X-Group-Sig: $SIG" \
     -d "Should fail.")

echo "Upload Status (Expected 403): $HTTP_CODE"

# Cleanup
kill $RM_PID
kill $CSP_PID

if [ "$HTTP_CODE" == "403" ]; then
    echo "SUCCESS: Revocation worked."
else
    echo "FAILURE: Revocation did not block user."
    exit 1
fi
```