# OCI
**Note:** You need to be in the root path of the repo!

Build local docker image:
```
$ docker build -t sos-milter:local -f OCI/Dockerfile .
```
Run it (with default ENV-values!):
```
$ docker run -d sos-milter:local
```
