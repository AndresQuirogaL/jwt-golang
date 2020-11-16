FROM golang:1.14

WORKDIR /go/src/app

ADD jwt_keys/ jwt_keys/
ADD jwt/ /go/src/jwt/
ADD script.go script.go

CMD ["go", "run", "script.go"]
