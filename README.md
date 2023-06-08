# SPF-on-submission-Milter - sos-milter
A lightweight, fast and thread-safe python3 [milter](http://www.postfix.org/MILTER_README.html) on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter).

The main goal of the **sos-milter** is to check the SPF-policy of a senders domain in term of mail submission scenario. Especially when forwarding of messages comming from *foreign* domains with restrictive SPF-policies (-all) takes place. The milter is also designed to check the correctness of SPF-policies for *own* domains (such as customers domains). In this case the milter expects that all *own* (not foreign) domains are managed in a LDAP server so that the milter can recognize them as such. For those domains the milter enforces checks regarding the appearence of particular SPF statements (include/s, ip4, ip6, ...) in the domain name system (DNS). Herefor the milter uses a regular expression which is part of the configuration. In this way the email service provider (ESP) running the sos-milter becomes able to check if his/her customers did set SPF-TXT-records correctly (as documented/expected) on each mail submission attempt and not just during the setup phase.

Further the sos-milter can be run in `test` or `reject` mode. In `test` mode the milter only does log policy violations which may be turned into metrics and used for baselining. Thus the `test` mode is recommended for first steps in an productive environment before enabling reject mode (if ever). In `reject` mode the milter fulfills policy enforcement and rejects every email submission requests that does not meet the configured expectations (expected SPF statements as regular expression).

### Deployment paradigm
Following the principles of [12-Factor-App](https://12factor.net/) for cloud native applications, the intention of this project is to deploy the milter as an [OCI compliant](https://www.opencontainers.org) container.

There´s nothing wrong to deploy the milter as a
* docker-compose deployment on a stand-alone docker host or a docker-swarm cluster
* stateless Kubernetes-workload (type: `Deployment`)
* local systemd unit, which is NOT a OCI-compliant was but works too ;-)

Please note, that according to the [3rd principle](https://12factor.net/config) of 12-Factor-App a cloud-native app is configured through environment variables, so this app does.

### Deployment with Docker - docker-compose.yml
The following [docker-compose](https://docs.docker.com/compose/) file demonstrates how such a setup could be orchestrated on a single docker host or on a docker swarm cluster. In this context we use [postfix](http://www.postfix.org) as our milter-aware MTA which connects to the milter via an UNIX-socket.

```
version: '3'

volumes:
  sosm_socket:

services:
  sos-milter:
    image: "sos-milter:<your_tag>"
    restart: unless-stopped
    environment:
      # default: info, possible: info, warning, error, debug
      LOG_LEVEL: debug
      # default: test, possible: test,reject
      MILTER_MODE: reject
      # Default: sos-milter
      MILTER_NAME: sos-milter
      # Default socket /socket/${MILTER_NAME}
      # MILTER_SOCKET: inet6:8020
      # MILTER_REJECT_MESSAGE: Message rejected due to security policy violation!
      # MILTER_TMPFAIL_MESSAGE: Message temporary rejected. Please try again later ;)

      # Expected Content of the spf-record, like a specific include
      # docker-compose pitfall: Dollar-sign ($) must be escaped as $$
      SPF_REGEX: '^.*include:secure-mailgate\.com.*$$'

      # If next-hop relay is one of the following, message will be ignored
      IGNORED_NEXT_HOPS: 'some-mailrelay.xyz:123, another.relay, and.so.on:125'

      # Search for sender domain in LDAP. Can be used to mark (add header)
      # and identify (log) internal sender domains with broken SPF-records
      # for further processing (log report or header-based routing).
      # After a message was marked with an additional header, it can be
      # routed other than usual (e.g. through a bounce-/fwd-relay)
      LDAP_ENABLED: 'some_value'
      LDAP_SERVER_URI: 'ldaps://some.ldap.server'
      LDAP_BINDDN: 'some-ldap-user-dn'
      LDAP_BINDPW: 'some-secret-pw'
      LDAP_SEARCH_BASE: 'ou=domains,dc=SLD,dc=TLD'
      # %d will be replaced by recognized 5321.env_from_domain
      LDAP_QUERY_FILTER: '(dc=%d)'
    hostname: sos-milter
    volumes:
    - "sosm_socket:/socket/:rw"

  postfix:
    depends_on:
    - sos-milter
    image: "your favorite postfix image"
    restart: unless-stopped
    hostname: postfix
    ports:
    - "465:465"
    volumes:
    - "./config/postfix:/etc/postfix:ro"
    - "sosm_socket:/socket/sos-milter/:rw"
```
