# prepare testing env
```
export TLD=de
export SLD=domain
export MILTER_MODE=reject
export MILTER_SOCKET=inet:12345
export LOG_LEVEL=debug
export SPF_REGEX="^.*include:_spf\.blah\.blub.*$"
export LDAP_ENABLED=yepp
export LDAP_SERVER_URI="ldap://ldap-master-staging.int.${SLD}.${TLD}"
export LDAP_SEARCH_BASE="ou=domains,dc=${SLD},dc=${TLD}"
export LDAP_QUERY_FILTER='(dc=%d)'
export IGNORED_NEXT_HOPS=test.next-host
```

# start milter
`python3 app/sos-milter.py`

# execute `miltertest`
First of all install the `miltertest` binary. Under debian based distros 
it´s located in the `opendkim-tools` package.

`miltertest -v -D socket=inet:12345@127.0.0.111 -s tests/miltertest.lua`