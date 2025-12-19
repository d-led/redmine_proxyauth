#! /usr/bin/env ruby
# Configure session cookie to use root path (/) so all paths share the same session.
# This prevents redirect loops caused by different paths having different session cookies.
# This runs as a Rails initializer, so Rails.application.config is available
#
# IMPORTANT: Rails does NOT automatically load initializers from plugin directories.
# This file must be copied to Redmine's main config/initializers/ directory to be executed.
# If this file is in the plugin directory, it will NOT run.
#
# NOTE: This file is named with "00_" prefix to ensure it runs BEFORE other initializers
# that might configure the session store, so the path is set early enough.

# Guard: Only run if this file is in the main config/initializers/ directory
# (not in the plugin's config/initializers/ subdirectory)
if __FILE__.include?('plugins/') && __FILE__.include?('config/initializers')
  Rails.logger.warn "[Session Config] Initializer is in plugin directory and will not be loaded. Copy to config/initializers/ to enable." if defined?(Rails.logger)
else
  # Set session cookie path to root
  # This must be set before any sessions are created or the session store is configured
  # CRITICAL: This must run before any session middleware is initialized
  Rails.application.config.session_options[:path] = '/'
  
  # Also ensure action_dispatch.session uses the same path
  # This covers all session-related configurations
  if Rails.application.config.respond_to?(:action_dispatch)
    Rails.application.config.action_dispatch.session ||= {}
    Rails.application.config.action_dispatch.session[:path] = '/'
  end
  
  # Log that we've set the session path
  Rails.logger.info "[Session Config] Session cookie path set to '/' to prevent redirect loops" if defined?(Rails.logger)
end
