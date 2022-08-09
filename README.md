# Decrypt Google Pay token with Golang

A Golang package to decrypt Google Pay tokens according 
to the [Google Pay docs](https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#decrypt-token) 
with no 3th party dependency.

## System requirements

- Golang 1.17+

## Pre-Requirements

Get your **merchant ID** from the [Google Pay business console](https://pay.google.com/business/console).
It should be in the format "merchant:**your merchant ID**".

For test environment it is always "merchant:12345678901234567890".

Generate your merchant private and public keys with [this instructions](https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#using-openssl).

## Usage

Install using : 

`go get github.com/nooize/google-token-decrypt`.

Usage example :

```golang

import  "github.com/nooize/google-token-decrypt"

merchantPrivateKey, err := ioutil.ReadFile("private.pem")

decoder, err := gpay.New(
    "merchant:12345678901234567890",
    merchantPrivateKey,
)
if err != nil {
	// handle error
}
 
data := []byte("{ ... encrypted token ... }")
 
token, err := decoder.Decrypt(data)
if err != nil {
    // handle error
}

```

if you always decrypt with single merchant ID, you can use default decryptor. 

To use default decryptor, simply define environment variable:
 - GOOGLE_PAY_MERCHANT_ID 
 - GOOGLE_PAY_MERCHANT_PRIVATE_KEY


Usage with default decoder :

```golang

import  "github.com/nooize/google-token-decrypt"
 
data := []byte("{ ... encrypted token ... }")
 
token, err := gpay.Decrypt(data)
if err != nil {
    // handle error
}

```

## Manage root signed certificates


GOOGLE_PAY_ROOT_SIGNED_KEYS_FILE
