
## How to build

- step 1, generate a tee signing key

```
openssl genrsa -out private.pem 4096
```

- step 2, build binary smpc app

```
$ DOCKER_BUILDKIT=1 docker build --secret id=signingkey,src=private.pem -o. .
```

