#!/bin/sh
#Create your Private key without a password
openssl genrsa -out domain.cz.key 1024

#Remove the password and encryption from your private key
openssl rsa -in domain.cz.encrypted.key -out domain.cz.key
 

#Create your Certificate Signing Request (CSR)
openssl req -new -key domain.cz.key -out domain.cz.csr

#Create your Certificate, Self-Sign your Certificate
openssl x509 -req -days 10000 -in domain.cz.csr -signkey domain.cz.key -out domain.cz.crt
 
#Creating a PEM file
cat domain.cz.key domain.cz.crt > domain.cz.pem

#Creating PFX file
openssl pkcs12 -inkey domain.cz.pem -in domain.cz.crt -export -out domain.cz.pfx
 
###On the server side copy domain.cz.pem to /etc/ssl/certs/
