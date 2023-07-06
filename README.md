# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-token.modulename=github.com/toanz/jwt-token"
  - "--experimental.plugins.jwt-token.version=v0.1.2"
```

Activate plugin in your config  

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
meta:
spec:
  plugin:
    jwt-token:
      secret: SECRET
      proxyHeaderName: injectedPayload
      authHeader: Authorization
      headerPrefix: Bearer
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-token@file"
```
