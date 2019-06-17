ARG http_proxy
ARG https_proxy
FROM debian
LABEL maintainer="Dominik Chilla <dominik@zwackl.de>"
LABEL git_repo="https://github.com/chillout2k/sos-milter"

ENV DEBIAN_FRONTEND=noninteractive \
 TZ=Europe/Berlin

RUN env; set -ex ; \
    apt-get -qq update \
 && apt-get -qq --no-install-recommends install \
     python3-pip python3-setuptools \
     libmilter1.0.1 libmilter-dev procps net-tools \
     gcc python3-dev netcat-traditional \
 && /usr/bin/pip3 install pymilter \
 && /usr/bin/pip3 install dnspython \
 && /bin/mkdir /config /socket /app \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY app/*.py /app/
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/python3", "/app/sos-milter.py"]
