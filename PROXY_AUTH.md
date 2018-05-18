# Proxy Auth

## Installation

Update `nipap-www/nipapwww/templates/login.html`

```
# NIPAP_DIR = e.g. /usr/lib/python2.7/dist-packages/nipapwww or /usr/local/lib/python2.7/dist-packages/nipap_www-0.29.6-py2.7.egg/nipapwww
$ cp nipap-www/nipapwww/controllers/proxy_auth.py "${NIPAP_DIR}/controllers/"
$ cp nipap-www/nipapwww/templates/login.html "${NIPAP_DIR}/templates/"
```

## Configuration


In `/etc/nipap/nipap.conf`:

```
# Example with default values
[auth.proxy]
header = X-Remote-User # The header/variable name to use for the user id
trusted_proxies = 127.0.0.1 # Trust headers comming form these ips (space seperated)
full_name_header = # name of the header to use for FullName e.g. displayName
rw_header =   # Name of the header used for checking write access
rw_values =   # What to match the rw_header field against. Has default space seperation
rw_split  =   # Use a different sperator than space/tab e.g. ; or , 
ro_header =   # Name of the header used for checking readonly access
ro_values =   # What to match the ro_header field against. Has default space seperation
ro_split  =   # 
use_env   =   # Force envirnment usage
debug     =   # If set will print out status, mappings and headers. See apache error log.
```

- The proxy auth module will check if the header field is present in the wsgi environment. If so it uses the environment varables. If not it uses the headers. 
  - When using environment the trusted_proxies vaiable is ignored.
- Setting `trusted_proxies` to `*` will accept headers from any host. This is should only be used for development, or if you are 100% certain that users cannot access NIPAP www directly.
- If a user is matched for both readonly and write, they will be given write access.


### Examples

```
# If X-Remote-User is set to anything then grant rw access
[auth.proxy]

# Specify who gets rw access
# Anyone who has an entitlement header with the a field that matches any of the values gets rw
# Others get ro access
[auth.proxy]
rw_header = entitlement
rw_split = ;
rw_values = noc;npe;dev 

# Specify who gets ro access
# Anyone who's header matches one of the specified fields gets ro
# **Others will get rw**
[auth.proxy]
ro_header = entitlement
ro_values = manager viewer

# Control both ro and rw
# If none of the groups matches, the user will not be authenticated.
[auth.proxy]
rw_header = entitlement
rw_values = noc npe dev 
ro_header = entitlement
ro_values = manager viewer

# Only allow specific rw people, deny everyone else
# Since ro_header is not set no one will be able to authenticate to ro
[auth.proxy]
rw_header = X-Remote-User
rw_values = markus htj jbr
ro_values = __DENY__ # The value does not matter but it must be set to deny ro access
```

### Apache or Nginx

Setup your authentication to protect `/proxy_auth/login`. If not using environment variables remember to make your proxy scrub/remove the headers you sepcify.
