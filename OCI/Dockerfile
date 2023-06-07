ARG PARENT_IMAGE=alpine:3.17
FROM ${PARENT_IMAGE}
LABEL maintainer="Dominik Chilla <dominik@zwackl.de>"
LABEL git_repo="https://github.com/chillout2k/sos-milter"

ADD ./requirements.txt /requirements.txt

RUN apk update \
  && apk add --no-cache python3 python3-dev py3-pip \
      gcc libc-dev libmilter-dev \
  && pip3 install -r requirements.txt \
  && apk del gcc libc-dev libmilter-dev python3-dev py3-pip \
  && apk add libmilter \
  && adduser -D sos-milter \
  && install -d -o sos-milter /socket \
  && rm -rf /var/cache/apk/* /requirements.txt

ADD ./app/ /app/
ADD ./OCI/cmd /cmd
RUN chown -R sos-milter /app /cmd \
  && chmod -R +x /app /cmd

VOLUME [ "/socket" ]

USER sos-milter
CMD [ "/cmd" ]