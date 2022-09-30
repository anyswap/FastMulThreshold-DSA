
## How to build gsmpc for TEE

- step 1, generate a tee signing key

```
openssl genrsa -out private.pem -3 3072

// due to the SGX limitation, should not modify any parameters of key pair generation
```

- step 2, build binary smpc app

```
DOCKER_BUILDKIT=1 docker build --secret id=signingkey,src=private.pem -o. .
```

