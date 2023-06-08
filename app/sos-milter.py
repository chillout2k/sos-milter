import Milter
import sys
import traceback
import os
import logging
import string
import random
import re
import dns.resolver
from ldap3 import (
  Server, Connection, NONE, set_config_parameter,
  SAFE_RESTARTABLE
)
from ldap3.core.exceptions import LDAPException

# Globals with mostly senseless defaults ;)
g_milter_name = 'sos-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Security policy violation!'
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
g_re_domain = re.compile(r'^.*@(\S+)$', re.IGNORECASE)
g_re_spf_regex = re.compile(r'.*', re.IGNORECASE)
g_loglevel = logging.INFO
g_milter_mode = 'test'
g_ignored_next_hops = {}
g_ldap_conn = None
g_ldap_server_uri = None
g_ldap_search_base = None
g_ldap_query_filter = None
g_ldap_binddn = ''
g_ldap_bindpw = ''

class SOSMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.reset()

  def reset(self):
    self.client_ip = None
    self.is_null_sender = False
    self.env_from = None
    self.env_from_domain = None
    self.is_env_from_domain_in_ldap = False
    self.spf_record = None
    self.queue_id = None
    self.next_hop = None
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )
    logging.debug(self.mconn_id + " RESET")

  # Not registered/used callbacks
  @Milter.nocallback
  def connect(self, IPname, family, hostaddr):
    return Milter.CONTINUE
  @Milter.nocallback
  def hello(self, heloname):
    return Milter.CONTINUE
  @Milter.nocallback
  def data(self):
    return Milter.CONTINUE
  @Milter.nocallback
  def header(self, name, hval):
    return Milter.CONTINUE
  @Milter.nocallback
  def eoh(self):
    return Milter.CONTINUE
  @Milter.nocallback
  def body(self, chunk):
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    # Instance member values remain within reused SMTP-connections!
    if self.client_ip is not None:
      # Milter connection reused!
      logging.debug(self.mconn_id + "/FROM connection reused!")
      self.reset()
    self.client_ip = self.getsymval('{client_addr}')
    if self.client_ip is None:
      logging.error(self.mconn_id + 
        " FROM exception: could not retrieve milter-macro ({client_addr})!"
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    else:
      logging.debug(self.mconn_id + 
        "/FROM client_ip={0}".format(self.client_ip)
      )
    try:
      # DSNs/bounces are not relevant
      if(mailfrom == '<>'):
        self.is_null_sender = True
        return Milter.CONTINUE
      mailfrom = mailfrom.replace("<","")
      mailfrom = mailfrom.replace(">","")
      self.env_from = mailfrom
      m = g_re_domain.match(self.env_from)
      if m is None:
        logging.error(self.mconn_id + "/FROM " +
          "Could not determine domain of 5321.from=" + self.env_from
        )
        self.is_null_sender = True
        return Milter.CONTINUE
      self.env_from_domain = m.group(1)
      logging.debug(self.mconn_id +
        "/FROM 5321_from_domain=" + self.env_from_domain
      )
      # Check if env_from_domain is in ldap
      if(g_ldap_conn is not None):
        filter = g_ldap_query_filter
        filter = filter.replace("%d", self.env_from_domain)
        logging.debug(self.mconn_id + "/FROM " +
          "LDAP query filter: {}".format(filter)
        )
        try:
          _, _, ldap_response, _ = g_ldap_conn.search(
            g_ldap_search_base,
            filter,
            attributes=[]
          )
          if len(ldap_response) != 0:
            self.is_env_from_domain_in_ldap = True
            logging.info(self.mconn_id + 
              "/FROM 5321.from_domain={0} found in LDAP".format(self.env_from_domain)
            )
        except LDAPException:
          logging.error(self.mconn_id + "/FROM " + traceback.format_exc())
        
      # Get TXT-SPF record of sender domain
      self.spf_record = self.get_spf_record(self.env_from_domain)
      return Milter.CONTINUE
    except:
      logging.error(self.mconn_id + 
        " FROM-EXCEPTION: " + traceback.format_exc()
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL

  def envrcpt(self, to, *str):
    if self.is_null_sender == True:
      return Milter.CONTINUE
    self.next_hop = self.getsymval('{rcpt_host}')
    if self.next_hop is None:
      logging.error(self.mconn_id + 
        "RCPT exception: could not retrieve milter-macro ({rcpt_host})"
      )
    else:
      logging.debug(self.mconn_id +
        "/RCPT Next-Hop: {0}".format(self.next_hop)
      )
    return Milter.CONTINUE

  # EOM is not optional and thus, always called by MTA
  def eom(self):
    # A queue-id will be generated after the first accepted RCPT TO
    # and therefore not available until DATA command
    self.queue_id = self.getsymval('i')
    if self.queue_id is None:
      logging.error(self.mconn_id +
        "EOM exception: could not retrieve milter-macro (i)!"
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    else:
      logging.debug(self.mconn_id + 
        "/EOM Queue-ID: {0}".format(self.queue_id)
      )

    if self.is_null_sender:
      logging.info(self.mconn_id + '/' + self.queue_id + 
        "/EOM Skipping bounce/DSN message"
      )
      return Milter.CONTINUE
    if self.spf_record is not None:
      logging.info(self.mconn_id + 
        '/' + self.queue_id + "/EOM " +
        "SPFv1: " + str(self.spf_record)
      )
      logging.debug(self.mconn_id + 
        '/' + self.queue_id + "/EOM " + 
        "next-hop=" + str(self.next_hop)
      )
      if re.match(r'^".+-all"$', self.spf_record, re.IGNORECASE) is not None:
        # SPF record is in restrictive mode
        logging.debug(self.mconn_id + '/' + self.queue_id + "/EOM " +
          "SPF-record is signaling a FAIL-policy (-all)"
        )
        if g_re_spf_regex.match(self.spf_record) is not None:
          logging.debug(self.mconn_id + '/' + self.queue_id + "/EOM" +
            " SPF-record of 5321_from_domain=" + self.env_from_domain +
            " permits us to relay this message"
          )
        else:
          # Expected 'include' not found in SPF-record
          if self.next_hop in g_ignored_next_hops:
            logging.info(self.mconn_id + 
              '/' + self.queue_id + "/EOM " + 
              "Passing message due to ignored next-hop=" + self.next_hop
            )
            return Milter.CONTINUE
          if self.is_env_from_domain_in_ldap and g_milter_mode != 'reject':
            logging.info(self.mconn_id + 
              '/' + self.queue_id + "/EOM " + 
              "5321_from_domain={0} (LDAP) has a broken SPF-record!".format(self.env_from_domain)
            )
            try:
              self.addheader('X-SOS-Milter', 'failed SPF-expectation')
              logging.debug(self.mconn_id + '/' 
                + self.queue_id + "/EOM " +
                'test-mode: X-SOS-Milter header was added. '
              )
            except:
              logging.error(self.mconn_id + 
                '/' + self.queue_id + "/EOM " + 
                "addheader() failed: " + traceback.format_exc()
              )
          ex = str(
            "SPF-record (-all) of 5321_from_domain=" 
            + self.env_from_domain + " does not permit us to relay this message!"
          )
          logging.info(self.mconn_id + '/' + self.queue_id + "/EOM " +
            "mode=" + g_milter_mode + ' client=' + self.client_ip + ' ' + ex
          )
          if g_milter_mode == 'reject': 
            self.setreply('550','5.7.1',
              self.mconn_id + ' ' + ex + ' ' + g_milter_reject_message
            )
            return Milter.REJECT
    else:
      logging.debug(self.mconn_id + 
        '/' + self.queue_id + "/EOM " +
        "No SPF-record found for {0}".format(self.env_from_domain)
      )
    return Milter.CONTINUE

  def abort(self):
    # Client disconnected prematurely
    logging.debug(self.mconn_id + "/ABORT")
    return Milter.CONTINUE

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    logging.debug(self.mconn_id + "/CLOSE")
    return Milter.CONTINUE
  
  def get_spf_record(self, from_domain):
    dns_response = None
    try:
      dns_response = dns.resolver.resolve(from_domain, 'TXT')
    except dns.resolver.NoAnswer as e:
      logging.warning(self.mconn_id + "/DNS " + e.msg)
      # accept message if DNS-resolver fails
      return None
    except dns.resolver.NXDOMAIN as e:
      logging.warning(self.mconn_id + 
        " /DNS " + e.msg
      )
      # accept message if DNS-resolver fails
      return None
    except:
      logging.error(self.mconn_id + 
        "/DNS Resolver-EXCEPTION: " + traceback.format_exc()
      )
      # accept message if DNS-resolver fails
      return None
    for rdata in dns_response:
      if re.match(r'^"v=spf1.*"$', rdata.to_text(), re.IGNORECASE):
        # we´ve got a SPF match!
        logging.debug(self.mconn_id + "/DNS SPFv1: {0}".format(rdata.to_text()))
        # check if spf-record includes a redirect!?
        m = re.match(
          r'^.*redirect=(?P<redirect_domain>.+).*"', 
          rdata.to_text(), 
          re.IGNORECASE
        )
        if m is not None:
          # SPF redirect clause found
          spf_redirect_domain = m.group('redirect_domain')
          logging.info(self.mconn_id + 
            "/DNS SPF-redirect: {}".format(spf_redirect_domain)
          )
          return self.get_spf_record(spf_redirect_domain)
        else:
          return rdata.to_text()

if __name__ == "__main__":
  if 'LOG_LEVEL' in os.environ:
    if re.match(r'^info$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.INFO
    elif re.match(r'^warn|warning$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.WARN
    elif re.match(r'^error$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.ERROR
    elif re.match(r'debug', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.DEBUG
  logging.basicConfig(
    filename=None, # log to stdout
    format='%(asctime)s: %(levelname)s %(message)s',
    level=g_loglevel
  )
  if 'MILTER_MODE' in os.environ:
    if re.match(r'^test|reject$',os.environ['MILTER_MODE'], re.IGNORECASE):
      g_milter_mode = os.environ['MILTER_MODE']
  logging.info("ENV[MILTER_MODE]: {}".format(g_milter_mode))
  if 'MILTER_NAME' in os.environ:
    g_milter_name = os.environ['MILTER_NAME']
  logging.info("ENV[MILTER_NAME]: {}".format(g_milter_name))
  if 'MILTER_SOCKET' in os.environ:
    g_milter_socket = os.environ['MILTER_SOCKET']
  logging.info("ENV[MILTER_SOCKET]: {}".format(g_milter_socket))
  if 'MILTER_REJECT_MESSAGE' in os.environ:
    g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
  logging.info("ENV[MILTER_REJECT_MESSAGE]: {}".format(g_milter_reject_message))
  if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
    g_milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
  logging.info("ENV[MILTER_TMPFAIL_MESSAGE]: {}".format(g_milter_tmpfail_message))
  if 'SPF_REGEX' in os.environ:
    try:
      g_re_spf_regex = re.compile(os.environ['SPF_REGEX'], re.IGNORECASE)
    except:
      logging.error("ENV[SPF_REGEX] exception: " + traceback.format_exc())
      sys.exit(1)
  logging.info("ENV[SPF_REGEX]: {}".format(g_re_spf_regex))
  if 'IGNORED_NEXT_HOPS' in os.environ:
    try:
      tmp_hops = os.environ['IGNORED_NEXT_HOPS'].split(',')
      for next_hop in tmp_hops:
        g_ignored_next_hops[next_hop] = 'ignore'
    except:
      logging.error("ENV[IGNORED_NEXT_HOPS] exception: " + traceback.format_exc())
      sys.exit(1)
    logging.info("ENV[IGNORED_NEXT_HOPS]: {}".format(g_ignored_next_hops))
  if 'LDAP_ENABLED' in os.environ:
    if 'LDAP_SERVER_URI' not in os.environ:
      logging.error("ENV[LDAP_SERVER_URI] is mandatory!")
      sys.exit(1)
    g_ldap_server_uri = os.environ['LDAP_SERVER_URI']
    logging.info("ENV[LDAP_SERVER_URI]: {}".format(g_ldap_server_uri))
    if 'LDAP_BINDDN' not in os.environ:
      logging.info("ENV[LDAP_BINDDN] not set! Continue...")
    else:
      g_ldap_binddn = os.environ['LDAP_BINDDN']
      logging.info("ENV[LDAP_BINDDN]: {}".format("***"))
    if 'LDAP_BINDPW' not in os.environ:
      logging.info("ENV[LDAP_BINDPW] not set! Continue...")
    else:
      g_ldap_bindpw = os.environ['LDAP_BINDPW']
      logging.info("ENV[LDAP_BINDPW]: {}".format("***"))
    if 'LDAP_SEARCH_BASE' not in os.environ:
      logging.error("ENV[LDAP_SEARCH_BASE] is mandatory!")
      sys.exit(1)
    g_ldap_search_base = os.environ['LDAP_SEARCH_BASE']
    logging.info("ENV[LDAP_SEARCH_BASE]: {}".format(g_ldap_search_base))
    if 'LDAP_QUERY_FILTER' not in os.environ:
      logging.error("ENV[LDAP_QUERY_FILTER] is mandatory!")
      sys.exit(1)
    g_ldap_query_filter = os.environ['LDAP_QUERY_FILTER']
    logging.info("ENV[LDAP_QUERY_FILTER]: {}".format(g_ldap_query_filter))
    try:
      set_config_parameter("RESTARTABLE_SLEEPTIME", 2)
      set_config_parameter("RESTARTABLE_TRIES", 2)
      set_config_parameter('DEFAULT_SERVER_ENCODING', 'utf-8')
      set_config_parameter('DEFAULT_CLIENT_ENCODING', 'utf-8')
      server = Server(g_ldap_server_uri, get_info=NONE)
      g_ldap_conn = Connection(server,
        g_ldap_binddn,
        g_ldap_bindpw,
        auto_bind=True, 
        raise_exceptions=True,
        client_strategy=SAFE_RESTARTABLE
      )
      logging.info("LDAP connection established. PID: " + str(os.getpid()))
    except LDAPException as e:
      print("LDAP-Exception: " + traceback.format_exc())
      sys.exit(1)
      
  try:
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = SOSMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    logging.info("Startup " + g_milter_name +
      "@socket: " + g_milter_socket +
      " in mode: " + g_milter_mode
    )
    Milter.runmilter(g_milter_name,g_milter_socket,timeout,True)
    logging.info("Shutdown " + g_milter_name)
  except:
    logging.error("MAIN-EXCEPTION: " + traceback.format_exc())