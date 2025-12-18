
# Dispatcher.to_prepare do
#   AccountController.send(:include, AccountControllerPatch) unless AccountController.included_modules.include? AccountControllerPatch
# end

require_relative 'lib/redmine_proxyauth/account_controller_patch'

Redmine::Plugin.register :redmine_oauth2_proxy_auth do
  name 'Redmine OAuth2 Proxy Authentication'
  author 'Dmitry Ledentsov'
  description 'Log in users via HTTP headers set by oauth2-proxy. Fork of redmine_proxyauth with enhanced GitHub OAuth2 support and seamless auto-login.'
  version '0.1.0'
  url 'https://github.com/d-led/redmine_oauth2_proxy_auth'
  author_url 'https://github.com/d-led'

  requires_redmine version_or_higher: '5.1.0'

  # No settings page needed - configuration is done via environment variables
  # Original redmine_proxyauth had OIDC settings, but we use oauth2-proxy which handles OAuth2/OIDC
end

# Rails automatically loads initializers from plugins/PLUGIN_NAME/config/initializers/
# The initializers will be loaded by Rails' initializer system automatically
# No explicit loading needed - Rails handles this for plugin directories
