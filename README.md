# sos-milter
A lightweight, fast and thread-safe python3 [milter](http://www.postfix.org/MILTER_README.html) on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter).

### Deployment paradigm
The intention of this project is to deploy the milter ALWAYS AND ONLY as an [OCI compliant](https://www.opencontainers.org) container. In this case it´s [docker](https://www.docker.com). The main reason is that I´m not interested (and familiar with) in building distribution packages like .rpm, .deb, etc.. Furthermore I´m not really a fan of 'wild and uncontrollable' software deployments like: get the code, compile it and finaly install the results 'somewhere' in the filesystem. In terms of software deployment docker provides wonderful possibilities, which I don´t want to miss anymore... No matter if in development, QA or production stage.

### docker-compose.yml
The following [docker-compose](https://docs.docker.com/compose/) file demonstrates how such a setup could be orchestrated on a single docker host or on a docker swarm cluster. In this context we use [postfix](http://www.postfix.org) as our milter-aware MTA.

```
version: '3'

volumes:
  sosm_socket:

services:
  sos-milter:
    image: "sos-milter/debian:19.06_master"
    restart: unless-stopped
    environment:
      LOG_LEVEL: debug
      # default: test, possible: test,reject
      MILTER_MODE: reject
      MILTER_NAME: sos-milter
      #MILTER_SOCKET: inet6:8020
      #MILTER_REJECT_MESSAGE: Message rejected due to security policy violation!
      #MILTER_TMPFAIL_MESSAGE: Message temporary rejected. Please try again later ;)
      SPF_REGEX: '^.*include:secure-mailgate\.com.*$$'
      IGNORED_NEXT_HOPS: 'some-mailrelay.xyz:123, another.relay, and.so.on:125'
      LDAP_ENABLED: 'some_value'
      LDAP_SERVER_URI: 'ldaps://some.ldap.server'
      LDAP_BINDDN: 'some-ldap-user-dn'
      LDAP_BINDPW: 'some-secret-pw'
      LDAP_SEARCH_BASE: 'ou=domains,dc=SLD,dc=TLD'
      LDAP_QUERY_FILTER: '(dc=%d)'
    hostname: sos-milter
    volumes:
    - "sosm_socket:/socket/:rw"

  postfix:
    depends_on:
    - sos-milter
    image: "postfix/alpine/amd64"
    restart: unless-stopped
    hostname: postfix
    ports:
    - "1587:587"
    volumes:
    - "./config/postfix:/etc/postfix:ro"
    - "sosm_socket:/socket/sos-milter/:rw"
```
