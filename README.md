## JWT GO (RS256)

### Generate private key

~~~
$ openssl genrsa -aes256 -out jwt-key.pem 4096
~~~

### Generate public key

~~~
$ openssl rsa -in jwt-key.pem -pubout > jwt-key.pub
~~~

## Image build

~~~
$ docker build . -t jwt-golang:0.1.0
~~~

## Run container

~~~
$ docker run --rm jwt-golang:0.1.0
~~~

### Functions

Encode JWT function: https://github.com/aaquirogal/jwt-golang/blob/main/jwt/jwt.go#L43

Verify JWT Token: https://github.com/aaquirogal/jwt-golang/blob/main/jwt/jwt.go#L89
