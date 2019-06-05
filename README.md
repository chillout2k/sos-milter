# sos-milter
A lightweight, fast and thread-safe python3 [milter](http://www.postfix.org/MILTER_README.html) on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter).

### Deployment paradigm
The intention of this project is to deploy the milter ALWAYS AND ONLY as an [OCI compliant](https://www.opencontainers.org) container. In this case it´s [docker](https://www.docker.com). The main reason is that I´m not interested (and familiar with) in building distribution packages like .rpm, .deb, etc.. Furthermore I´m not really a fan of 'wild and uncontrollable' software deployments like: get the code, compile it and finaly install the results 'somewhere' in the filesystem. In terms of software deployment docker provides wonderful possibilities, which I don´t want to miss anymore... No matter if in development, QA or production stage.

### docker-compose.yml
The following [docker-compose](https://docs.docker.com/compose/) file demonstrates how such a setup could be orchestrated on a single docker host or on a docker swarm cluster. In this context we use [postfix](http://www.postfix.org) as our milter-aware MTA.

```
*TODO*
```
