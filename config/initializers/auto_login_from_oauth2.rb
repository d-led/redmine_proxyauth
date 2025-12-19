#! /usr/bin/env ruby
# Lightweight auto-login from oauth2-proxy headers.
# 
# Goal:
# - Do NOT change redmine_proxyauth behaviour for /login (it still owns
#   user provisioning and admin promotion).
# - On every request that already has trusted OAuth2 headers, ensure
#   User.current and the Rails session are in sync, so that Redmine's
#   own before_actions (like :session_expiration / :require_login) see
#   the user as logged in and do not trigger redirect loops.
#
# This is intentionally simple and narrow:
# - We only ever look up an existing User by email.
# - We do NOT create users here; redmine_proxyauth does that on /login.
# - We run before other filters (prepend: true) so that session_expiration
#   sees a logged-in user when oauth2-proxy says the request is authenticated.

# IMPORTANT: Rails does NOT automatically load initializers from plugin directories.
# This file must be copied to Redmine's main config/initializers/ directory to be executed.
# If this file is in the plugin directory, it will NOT run.

# Guard: Only run if this file is in the main config/initializers/ directory
# (not in the plugin's config/initializers/ subdirectory)
if __FILE__.include?('plugins/') && __FILE__.include?('config/initializers')
  Rails.logger.warn "[Proxyauth] Initializer is in plugin directory and will not be loaded. Copy to config/initializers/ to enable." if defined?(Rails.logger)
elsif defined?(Rails) && Rails.application
  # Execute immediately when initializer is loaded, not in to_prepare
  # This ensures it runs in production and before requests are handled
  Rails.logger.info "[Proxyauth] Loading auto_login_from_oauth2 initializer" if defined?(Rails.logger)
  Rails.application.config.to_prepare do
    Rails.logger.info "[Proxyauth] to_prepare block executing for auto_login_from_oauth2" if defined?(Rails.logger)
    next unless defined?(ApplicationController) && defined?(User)

    Rails.logger.info "[Proxyauth] Patching ApplicationController with auto_login_from_oauth2" if defined?(Rails.logger)
    ApplicationController.class_eval do
      before_action :auto_login_from_oauth2, prepend: true

      private

      def auto_login_from_oauth2
        # Take the email from the trusted proxy headers first
        email = request.headers['X-Auth-Request-Email'] ||
                request.headers['X-Forwarded-Email']
        user_name = request.headers['X-Auth-Request-User'] ||
                    request.headers['X-Forwarded-User']

        # If no OAuth2 headers, check if user is already logged in (normal session)
        if email.blank?
          if User.current&.logged?
            Rails.logger.debug "[Proxyauth] auto_login_from_oauth2: User already logged in (#{User.current.login}), no OAuth2 headers"
          else
            Rails.logger.debug "[Proxyauth] auto_login_from_oauth2: No email header found on #{request.fullpath}"
          end
          return
        end

        Rails.logger.info "[Proxyauth] auto_login_from_oauth2: Found email header: #{email} on #{request.fullpath}"

        # Find user from OAuth2 email
        user = User.find_by_mail(email)
        
        # CRITICAL: If OAuth2 headers are present, they are the source of truth
        # We MUST clear any stale session if the current user doesn't match OAuth2
        # This must happen BEFORE checking if user exists, to prevent redirect loops
        if User.current&.logged?
          if user.nil?
            # OAuth2 says this email, but user doesn't exist in Redmine
            # Clear the stale session - we'll let redmine_proxyauth create the user on /login
            Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: Stale session detected! Current user: #{User.current.login} (#{User.current.mail}), but OAuth2 user #{email} doesn't exist. Clearing stale session."
            reset_session
            User.current = nil
          elsif User.current.id != user.id
            # OAuth2 says different user - clear the stale session
            Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: Stale session detected! Current user: #{User.current.login} (#{User.current.mail}), OAuth2 user: #{user.login} (#{email}). Clearing stale session."
            reset_session
            User.current = nil
          elsif User.current.id == user.id
            # User matches OAuth2 - we're good, but verify they're still active
            if user&.active?
              Rails.logger.debug "[Proxyauth] auto_login_from_oauth2: User already logged in and matches OAuth2 (#{User.current.login})"
              return
            else
              # User exists but is inactive - clear session
              Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: User #{email} is inactive. Clearing session."
              reset_session
              User.current = nil
            end
          end
        end
        
        # If user doesn't exist, let redmine_proxyauth handle creation on /login
        # But if user exists, auto-login them even on /login route
        if user.nil?
          Rails.logger.debug "[Proxyauth] auto_login_from_oauth2: User with email #{email} not found"
          # Only skip if we're on /login (let proxyauth create the user)
          # On other routes, we can't auto-login a non-existent user
          if request.path == '/login' || request.path.start_with?('/login?')
            Rails.logger.debug "[Proxyauth] auto_login_from_oauth2: Letting redmine_proxyauth handle user creation on /login"
            return
          else
            Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: User not found and not on /login, cannot auto-login"
            return
          end
        end
        
        # User exists - auto-login them even on /login route
        # This provides seamless experience: if user already exists, they're logged in immediately

        # Do not auto-login inactive users
        unless user&.active?
          Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: User #{email} is not active"
          return
        end

        # Optionally keep name in sync with headers (non-empty values only).
        if user_name.present?
          first, last = user_name.split(' ', 2)
          changed = false
          if first.present? && user.firstname != first
            user.firstname = first
            changed = true
          end
          if last.present? && last != '' && user.lastname != last
            user.lastname = last
            changed = true
          end
          user.save(validate: false) if changed
        end

        # Align Redmine's current user and session with the proxy identity.
        # CRITICAL: Set User.current BEFORE setting session, as Redmine's session methods may check it
        User.current = user
        
        # Use Redmine's proper session method if available
        # This method sets both User.current and the session correctly
        if respond_to?(:start_user_session, true)
          send(:start_user_session, user)
          Rails.logger.info "[Proxyauth] auto_login_from_oauth2: Used start_user_session for #{user.login}"
        else
          # Fallback: set the standard session keys manually.
          session[:user_id] = user.id
          # Ensure User.current is set (don't reload from session as it might not be persisted yet)
          User.current = user
          Rails.logger.info "[Proxyauth] auto_login_from_oauth2: Set session manually for #{user.login}"
        end
        
        # CRITICAL: Ensure session is marked as changed so it gets persisted
        # The session middleware will handle writing it to the response
        # We need to ensure it's loaded and marked as dirty
        if session.respond_to?(:loaded?) && !session.loaded?
          session.load!
        end
        # Explicitly mark session as changed to ensure it's persisted
        if session.respond_to?(:[]=)
          # Touch the session to mark it as changed
          session[:user_id] = user.id unless session[:user_id] == user.id
        end

        # Verify the login worked
        # Don't reload User.current from session here - we just set it above
        if User.current&.logged?
          Rails.logger.info "[Proxyauth] auto_login_from_oauth2: ✅ Successfully auto-logged in #{user.login} on #{request.fullpath}"
        else
          Rails.logger.warn "[Proxyauth] auto_login_from_oauth2: ⚠️ User.current.logged? is false after setting session. User.current: #{User.current&.id}, session[:user_id]: #{session[:user_id]}"
        end
      rescue => e
        Rails.logger.error "[Proxyauth] auto_login_from_oauth2 error: #{e.class}: #{e.message}"
        Rails.logger.error "[Proxyauth] Backtrace: #{e.backtrace.first(10).join(', ')}" if e.backtrace
      end
  end
else
  Rails.logger.warn "[Proxyauth] auto_login_from_oauth2 initializer skipped (Rails not available or file in plugin directory)" if defined?(Rails.logger)
end

