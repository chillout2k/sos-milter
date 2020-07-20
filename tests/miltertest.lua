-- https://mopano.github.io/sendmail-filter-api/constant-values.html#com.sendmail.milter.MilterConstants
-- http://www.opendkim.org/miltertest.8.html

--conn = mt.connect("inet:8020@10.42.50.2")
conn = mt.connect("inet:12345@127.0.0.1")
if conn == nil then
  error "mt.connect() failed"
end

mt.set_timeout(3)

-- 5321.FROM + MACROS
mt.macro(conn, SMFIC_MAIL, "i", "test-id",'{rcpt_host}', "test.next-hostx")
if mt.mailfrom(conn, "dominik@dc-it-con.de") ~= nil then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.mailfrom() unexpected reply"
end

-- 5321.RCPT
if mt.rcptto(conn, "info@dc-it-con.de") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.rcptto() unexpected reply"
end

-- EOM
if mt.eom(conn) ~= nil then
  error "mt.eom() failed"
end
mt.echo("EOM: " .. mt.getreply(conn))
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("EOM-continue")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  mt.echo("EOM-reject")
end

if not mt.eom_check(conn, MT_HDRADD, "X-SOS-Milter") then
  mt.echo("no header added")
else
  mt.echo("X-SOS-Milter header added -> LDAP-Domain with broken SPF")
end

-- DISCONNECT
mt.disconnect(conn)