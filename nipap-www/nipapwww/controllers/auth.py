import logging

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect

from nipapwww.lib.base import BaseController, render

from nipap.authlib import AuthFactory, AuthError
from nipap.nipapconfig import NipapConfig

from ConfigParser import NoOptionError

log = logging.getLogger(__name__)

class AuthController(BaseController):
    """ Deals with authentication.
    """

    requires_auth = False


    def login(self):
        """ Show login form.
        """

        if request.method != 'POST':
            cfg = NipapConfig()
            try:
                c.welcome_message = cfg.get('www', 'welcome_message')
            except NoOptionError:
                pass

            return render('login.html')

        # Verify username and password.
        try:
            auth_fact = AuthFactory()
            auth = auth_fact.get_auth(request.params.get('username'), request.params.get('password'), 'nipap')
            if not auth.authenticate():
                c.error = 'Invalid username or password'
                return render('login.html')
        except AuthError as exc:
            c.error = 'Authentication error'
            return render('login.html')

        # Mark user as logged in
        session['user'] = auth.username
        session['full_name'] = auth.full_name
        session['readonly'] = auth.readonly
        session['current_vrfs'] = {}
        session.save()

        # Send user back to the page he originally wanted to get to
        if session.get('path_before_login'):
            redirect(session['path_before_login'])

        else:
            # if previous target is unknown just send the user to a welcome page
            redirect(url(controller='prefix', action='list'))

    def _proxy_auth_config(self):
        cfg = NipapConfig()
        auth_proxy_configured = cfg.has_section('auth.proxy')

        auth_header = 'X-Remote-User'
        if cfg.has_option('auth.proxy', 'header'):
            auth_header = cfg.get('auth.proxy', 'header')

        trusted_proxies = ['127.0.0.1']
        if cfg.has_option('auth.proxy', 'trusted_proxies'):
            trusted_proxies = cfg.get('auth.proxy', 'trusted_proxies').split()

        full_name_header = None
        if cfg.has_option('auth.proxy', 'full_name_header'):
            full_name_header = cfg.get('auth.proxy', 'full_name_header')

        rw_header = None
        if cfg.has_option('auth.proxy', 'rw_header'):
            rw_header = cfg.get('auth.proxy', 'rw_header')

        ro_header = None
        if cfg.has_option('auth.proxy', 'ro_header'):
            ro_header = cfg.get('auth.proxy', 'ro_header')

        rw_split = None
        if cfg.has_option('auth_proxy', 'rw_split'):
            rw_split = cfg.get('auth_proxy', 'rw_split')

        ro_split = None
        if cfg.has_option('auth.proxy', 'ro_split'):
            ro_split = cfg.get('auth_proxy', 'ro_split')

        rw_values = None
        if cfg.has_option('auth.proxy', 'rw_values'):
            rw_values = cfg.get('auth.proxy', 'rw_values').split(rw_split)

        ro_values = None
        if cfg.has_option('auth.proxy', 'ro_values'):
            ro_values = cfg.get('auth.proxy', 'ro_values').split(ro_split)

        # Pre checks
        # XXX: proper cider check?
        is_trusted = request.remote_addr in trusted_proxies
        if '*' in trusted_proxies:
            is_trusted = True

        user = None
        if auth_header:
            user = request.headers.Get(auth_header)
        full_name = None
        if full_name_header:
            full_name = request.headers.Get(full_name_header)

        # Check if user has write access
        # Default is rw if nothing has been set
        is_readonly = False
        if ro_header and ro_values:
            # split rw_header if rw_split
            user_groups = request.headers.Get(ro_header, '').split(ro_split)
            # Check if any user group is in ro_values
            if [g for g in user_groups if g in ro_values]:
                is_readonly = True
        if rw_header and rw_values:
            user_groups = request.headers.Get(ro_header, '').split(rw_split)
            # Check if any user group is in ro_values
            if [g for g in user_groups if g in rw_values]:
                is_readonly = False
            elif ro_values and not is_readonly:
                # XXX: Auth failure!
                pass
            else:
                is_readonly = False

        return {
            # Check if proxy auth enabled
            'is_configured': auth_proxy_configured,
            'is_trusted': is_trusted,
            'is_ready': auth_proxy_configured and is_trusted,
            'user': user,
            'is_readonly': is_readonly,
            'full_name': full_name
        }

    def proxy_auth(self):
        """ Proxy auth handling
        """
        proxy_conf = self._proxy_auth_config()
        if not proxy_conf['is_ready'] or not proxy_conf['user']:
            if not proxy_conf['is_trusted']:
                log.Warn('Untrusted proxy {} tried to log in'.format(request.remote_addr))
            # Consider 404 instead?
            redirect(url(controller='auth', action='login'))
            return

        # Create session
        session['user'] = proxy_conf['user']
        session['full_name'] = proxy_conf['full_name']
        session['readonly'] = proxy_conf['is_readonly']
        session['current_vrfs'] = {}
        session.save()

        # handle redirect back
        redirect(session['path_before_login'] or url(controller='prefix', action='list'))

    def logout(self):
        """ Log out the user and display a confirmation message.
        """

        # remove session
        session.delete()

        return render('login.html')
