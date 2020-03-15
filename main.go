package main

/*
#cgo CFLAGS: -I/usr/openssl/include
#cgo LDFLAGS: -lcrypto
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char errmessage[2048] = {0};
int cb_pass(char *buf, int size, int rwflag, void *u) {
    char *pass = (char *)u;
    if (u == NULL)
        return 0;
    int len = strlen(pass);
    if (len > size)
        len = size;
    memcpy(buf, pass, len);

    return len;
}

RSA* get_rsa_from_public_key(char *pem)
{
    RSA *rsa = NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pem, strlen(pem));
    EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    rsa = EVP_PKEY_get1_RSA(evp_key);

    return rsa;
}

RSA* get_rsa_from_private_key(char *pem, char *password)
{
    RSA *rsa = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pem, strlen(pem));
    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, cb_pass, password);

    return rsa;
}

RSA *rsa_read_pem_public(char *pem){
    FILE *fp = fopen(pem,"r");
    RSA *public_key = NULL;

    if(fp == NULL){
        if ((public_key = get_rsa_from_public_key(pem)) && public_key == NULL) {
            snprintf(errmessage,sizeof(errmessage),"failed to load public key");
            return NULL;
        }

        return public_key;
    }

    public_key = RSA_new();
    if (!PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL)){
        snprintf(errmessage,sizeof(errmessage),"%s",ERR_error_string(ERR_get_error(),NULL));
        RSA_free(public_key);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    return public_key;
}

RSA* rsa_read_pem_private(char *pem, char *password){
    if (password != NULL && password[0] == 0) {
        password = NULL;
    }

    FILE *fp = fopen(pem,"r");
    RSA *private_key = NULL;
    if(fp == NULL){
        if ((private_key = get_rsa_from_private_key(pem, password)) && private_key == NULL) {
            snprintf(errmessage,sizeof(errmessage),"failed to load private key");
            return NULL;
        }
        return private_key;
    }

    private_key = RSA_new();
    if (!PEM_read_RSAPrivateKey(fp, &private_key, cb_pass, password)){
    //if (!PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL)){
        snprintf(errmessage,sizeof(errmessage),"%s",ERR_error_string(ERR_get_error(),NULL));
        RSA_free(private_key);
        return NULL;
    }
    return private_key;
}

int rsa_private_encrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding, char* password){
    RSA *private_key = rsa_read_pem_private(pem, password);
    if(!private_key){
        return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(private_key));
    int n = RSA_private_encrypt(fromSize,from,(unsigned char *)*to,private_key,padding);
    if (n == -1){
        snprintf(errmessage,sizeof(errmessage),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(private_key);
    return n;
}

int rsa_public_decrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
    RSA* public_key = rsa_read_pem_public(pem);
    if(!public_key){
        return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(public_key));
    int n = RSA_public_decrypt(fromSize,from,(unsigned char *)*to,public_key,padding);
    if (n == -1){
        snprintf(errmessage,sizeof(errmessage),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(public_key);
    return n;
}
*/
import "C"
import "unsafe"
import "fmt"

const (
	RSA_PKCS1_PADDING = C.RSA_PKCS1_PADDING
	RSA_NO_PADDING    = C.RSA_NO_PADDING
)

func PublicDecrypt(from []byte, pem string, padding int) ([]byte, error) {
	var to *C.char = nil

	if n := C.rsa_public_decrypt(C.int(len(from)),
		(*C.uchar)(unsafe.Pointer(&from[0])),
		(**C.char)(unsafe.Pointer(&to)),
		C.CString(pem),
		C.int(padding)); n < 0 {
		return nil, fmt.Errorf("%s", C.GoString(&C.errmessage[0]))
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}

func PrivateEncrypt(from []byte, pem string, padding int, password string) ([]byte, error) {
	var to *C.char = nil

	if n := C.rsa_private_encrypt(C.int(len(from)),
		(*C.uchar)(unsafe.Pointer(&from[0])),
		(**C.char)(unsafe.Pointer(&to)),
		C.CString(pem),
		C.int(padding),
		C.CString(password)); n < 0 {
		return nil, fmt.Errorf("%s", C.GoString(&C.errmessage[0]))
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}

func init() {
	C.ERR_load_ERR_strings()
}

func main() {
	fmt.Println("ok")
}
