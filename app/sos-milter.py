import Milter
import sys
import traceback
import os
import logging
import string
import random
import re
import dns.resolver
from timeit import default_timer as timer

# Globals with mostly senseless defaults ;)
g_milter_name = 'sos-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Security policy violation!'
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
g_re_domain = re.compile(r'^\S*@(\S+)$', re.IGNORECASE)
g_re_spf_regex = re.compile(r'.*', re.IGNORECASE)
g_re_expected_txt_data = ''
g_loglevel = logging.INFO
g_milter_mode = 'test'
g_milter_default_policy = 'reject'

class SOSMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.time_start = timer()
    self.env_from = None
    self.env_from_domain = None
    self.spf_record = None
    self.add_header = False
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )
  # Not registered/used callbacks
  @Milter.nocallback
  def connect(self, IPname, family, hostaddr):
    return Milter.CONTINUE
  @Milter.nocallback
  def hello(self, heloname):
    return Milter.CONTINUE
  @Milter.nocallback
  def envrcpt(self, to, *str):
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
    try:
      mailfrom = mailfrom.replace("<","")
      mailfrom = mailfrom.replace(">","")
      self.env_from = mailfrom
      m = g_re_domain.match(self.env_from)
      if m is None:
        logging.error(self.mconn_id + "/FROM " +
          "Could not determine domain of 5321.from=" + self.env_from
        )
        self.setreply('450','4.7.1', g_milter_tmpfail_message)
        return Milter.TEMPFAIL
      self.env_from_domain = m.group(1)
      logging.debug(self.mconn_id +
        "/FROM env_from_domain=" + self.env_from_domain
      )
      # Get TXT record of sender domain
      dns_response = None
      try:
        dns_response = dns.resolver.query(self.env_from_domain, 'TXT')
      except:
        logging.error("DNS-Resolver-EXCEPTION: " + traceback.format_exc())
        # accept message if DNS-resolver fails
        return Milter.CONTINUE
      spf_count = 0
      for rdata in dns_response:
        if re.match(r'^"v=spf1.*"$', rdata.to_text(), re.IGNORECASE):
          # we´ve got a SPF match!
          spf_count += 1
          self.spf_record = rdata.to_text()
          logging.debug(self.mconn_id + "/FROM " +
            "SPFv1: " + self.spf_record
          )
          if re.match(r'^".+-all"$', self.spf_record, re.IGNORECASE) is not None:
            # SPF record is in agressive mode!
            if g_re_spf_regex.match(self.spf_record) is not None:
              logging.debug(self.mconn_id + "/FROM" +
                " SPF-record of sender-domain " + self.env_from_domain +
                " permits us to relay this message"
              )
            else:
              ex = "Agressive SPF-record (-all) of sender-domain " + self.env_from_domain + " does not permit us to relay this message!"
              # Expected 'include' not found in SPF-record
              logging.debug(self.mconn_id + "/FROM " + ex)
              if g_milter_mode == 'test':
                logging.debug(self.mconn_id + "/FROM " +
                  ' test-mode: X-SOS-Milter header will be added'
                )
                self.add_header = True
              else:
                logging.error(self.mconn_id + "/FROM " + ex)
                self.setreply('550','5.7.1',
                  self.mconn_id + ' ' + ex + ' Please contact your postmaster!'
                )
                return Milter.REJECT
      if spf_count > 1:
        ex = "Sender-domain " + self.env_from_domain + " has more than one SPF-TXT-records in DNS!"""
        logging.error(self.mconn_id + "/FROM " + ex)
        if g_milter_mode == 'reject':
          self.setreply('550','5.7.1',
            self.mconn_id + ' ' + ex + ' Please contact your postmaster!'
          )
          return Milter.REJECT
      return Milter.CONTINUE
    except:
      logging.error("FROM-EXCEPTION: " + traceback.format_exc())
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL

  def eom(self):
    # EOM is not optional and thus, always called by MTA
    if self.add_header == True:
      self.addheader(
        'X-SOS-Milter',
        self.mconn_id + ' ' + self.env_from_domain + ': failed SPF-expectation'
      )
    return Milter.CONTINUE

  def abort(self):
    # Client disconnected prematurely
    return Milter.CONTINUE

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    return Milter.CONTINUE

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
  if 'MILTER_DEFAULT_POLICY' in os.environ:
    if re.match(r'^reject|permit$',os.environ['MILTER_DEFAULT_POLICY'], re.IGNORECASE):
      g_milter_default_policy = str(os.environ['MILTER_DEFAULT_POLICY']).lower()
    else:
      logging.warn("MILTER_DEFAULT_POLICY invalid value: " +
        os.environ['MILTER_DEFAULT_POLICY']
      )
  if 'MILTER_NAME' in os.environ:
    g_milter_name = os.environ['MILTER_NAME']
  if 'MILTER_SOCKET' in os.environ:
    g_milter_socket = os.environ['MILTER_SOCKET']
  if 'MILTER_REJECT_MESSAGE' in os.environ:
    g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
  if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
    g_milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
  if 'SPF_REGEX' in os.environ:
    try:
      g_re_spf_regex = re.compile(os.environ['SPF_REGEX'], re.IGNORECASE)
    except:
      logging.error("ENV[SPF_REGEX] exception: " + traceback.format_exc())
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
