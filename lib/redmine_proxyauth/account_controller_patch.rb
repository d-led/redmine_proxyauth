module RedmineProxyauth
  module AccountControllerPatch

    def login
      if params.key?("form_login") || request.post?
        super
        return
      end

      if User.current.logged?
        redirect_back_or_default home_url, :referer => true
        return
      end

      email, given_name, family_name = "", "", ""
      jwt_decoded = false
      github_api_used = false

      # Try to get user info from JWT token (for OIDC providers like Google, Azure, etc.)
      # Check both X-Auth-Request-Access-Token and X-Forwarded-Access-Token headers
      token = request.headers['X-Auth-Request-Access-Token'] || request.headers['X-Forwarded-Access-Token']
      Rails.logger.debug "[Proxyauth] Token present: #{token.present?}, header keys: #{request.headers.env.keys.grep(/ACCESS_TOKEN|AUTH_REQUEST/).join(', ')}"
      if token.present?
        begin
          decoded_token = JWT.decode token, nil, false
          given_name = decoded_token[0]["given_name"] || decoded_token[0]["name"] || ""
          family_name = decoded_token[0]["family_name"] || ""
          email = decoded_token[0]["email"] || ""
          jwt_decoded = true
        rescue JWT::DecodeError => e
          Rails.logger.debug "Token is not a JWT (expected for GitHub OAuth2): #{e.message}"
          # Token is not a JWT (e.g., GitHub opaque access token) - try GitHub API
          Rails.logger.info "[Proxyauth] Attempting to fetch user info from GitHub API with access token"
          begin
            # Use GitHub API to get user information
            require 'net/http'
            require 'json'
            
            uri = URI('https://api.github.com/user')
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.read_timeout = 5
            http.open_timeout = 5
            
            api_request = Net::HTTP::Get.new(uri)
            api_request['Authorization'] = "token #{token}"
            api_request['Accept'] = 'application/vnd.github.v3+json'
            api_request['User-Agent'] = 'Redmine-Proxyauth-Plugin'
            
            response = http.request(api_request)
            
            if response.code == '200'
              user_data = JSON.parse(response.body)
              email = user_data['email'] || ""
              full_name = user_data['name'] || ""
              
              # If email is not in public profile, try /user/emails endpoint
              if email.blank?
                Rails.logger.info "[Proxyauth] Email not in public profile, fetching from /user/emails endpoint"
                emails_uri = URI('https://api.github.com/user/emails')
                emails_request = Net::HTTP::Get.new(emails_uri)
                emails_request['Authorization'] = "token #{token}"
                emails_request['Accept'] = 'application/vnd.github.v3+json'
                emails_request['User-Agent'] = 'Redmine-Proxyauth-Plugin'
                
                emails_response = http.request(emails_request)
                if emails_response.code == '200'
                  emails_data = JSON.parse(emails_response.body)
                  # Find primary email or first verified email
                  primary_email = emails_data.find { |e| e['primary'] && e['verified'] }
                  email = primary_email ? primary_email['email'] : (emails_data.find { |e| e['verified'] }&.dig('email') || "")
                  Rails.logger.info "[Proxyauth] Retrieved email from /user/emails: #{email}"
                else
                  Rails.logger.warn "[Proxyauth] /user/emails returned status #{emails_response.code}: #{emails_response.body[0..200]}"
                end
              end
              
              # Parse full name into first and last name
              if full_name.present?
                name_parts = full_name.split(' ', 2)
                given_name = name_parts[0] || ""
                family_name = name_parts[1] || ""
                Rails.logger.info "[Proxyauth] Parsed name: firstname=#{given_name}, lastname=#{family_name}"
              else
                Rails.logger.warn "[Proxyauth] GitHub API returned no name field"
              end
              
              github_api_used = true
              Rails.logger.info "[Proxyauth] Retrieved user info from GitHub API: #{email} / #{full_name}"
            else
              Rails.logger.warn "[Proxyauth] GitHub API returned status #{response.code}: #{response.body[0..200]}"
            end
          rescue StandardError => e
            Rails.logger.error "[Proxyauth] Failed to fetch user info from GitHub API: #{e.class}: #{e.message}"
            Rails.logger.error "[Proxyauth] Backtrace: #{e.backtrace.first(5).join(', ')}" if e.backtrace
            # Fall through to header-based fallback
          end
        end
      end

      # Fall back to headers if JWT decode failed and GitHub API didn't work
      if email.blank?
        email = request.headers['X-Auth-Request-Email'] || request.headers['X-Forwarded-Email'] || ""
      end
      
      if given_name.blank? && family_name.blank?
        # Try to extract name from user header (format: "First Last" or "username")
        user_header = request.headers['X-Auth-Request-User'] || request.headers['X-Forwarded-User'] || ""
        if user_header.present?
          name_parts = user_header.split(' ', 2)
          given_name = name_parts[0] || ""
          family_name = name_parts[1] || ""
        end
      end

      if email.blank?
        flash[:error] = l(:proxyauth_missing_token)
        return
      end

      auth_method = jwt_decoded ? "JWT" : (github_api_used ? "GitHub API" : "Headers")
      Rails.logger.info "Found user info for: #{email} / #{given_name} #{family_name} (Auth: #{auth_method})"

      user = User.find_by_mail(email)
      if user.nil?
        # Auto-create user only when using GitHub API or header-based auth
        # For JWT-based auth (OIDC), preserve original behavior: require user to exist
        if jwt_decoded
          Rails.logger.error "User with email #{email} not found."
          flash[:error] = l(:proxyauth_user_not_found, email: email)
          return
        else
          # GitHub API or header-based auth: auto-provision user
          Rails.logger.info "User with email #{email} not found. Creating new user (#{auth_method})."
          # Redmine requires lastname to be present, so use a default if not provided
          default_lastname = family_name.presence || "User"
          user = User.new(
            mail: email,
            firstname: given_name.presence || email.split('@').first,
            lastname: default_lastname,
            login: email.split('@').first,
            language: Setting.default_language,
            status: User::STATUS_ACTIVE
          )
          user.login = email.split('@').first if user.login.blank?
          # Generate a random password (user won't need it with proxyauth)
          user.password = SecureRandom.hex(32)
          user.password_confirmation = user.password
          
          unless user.save
            Rails.logger.error "Failed to create user with email #{email}: #{user.errors.full_messages.join(', ')}"
            flash[:error] = l(:proxyauth_user_not_found, email: email)
            return
          end
          Rails.logger.info "Created new user: #{email}"
          
          # Check if user should be promoted to admin immediately
          admin_emails = ENV['REDMINE_ADMIN_EMAILS'].to_s.split(',').map(&:strip).reject(&:empty?)
          if admin_emails.include?(email) && !user.admin?
            user.update_columns(admin: true, status: User::STATUS_ACTIVE)
            Rails.logger.info "[Proxyauth] Promoted newly created user #{email} to admin"
          end
        end
      else
        # Name matching: strict for JWT (original behavior), lenient for GitHub API/headers
        if jwt_decoded
          # Original behavior: strict name matching for JWT-based auth
          if user.firstname != given_name || user.lastname != family_name
            Rails.logger.error "User with email #{email} has changed name from #{user.firstname} #{user.lastname} to #{given_name} #{family_name}. Not logging in."
            flash[:error] = l(:proxyauth_user_inconsistent)
            return
          end
        else
          # GitHub API or header-based auth: update name if changed, but don't block login
          if (given_name.present? && user.firstname != given_name) || (family_name.present? && user.lastname != family_name)
            Rails.logger.info "User with email #{email} has changed name from #{user.firstname} #{user.lastname} to #{given_name} #{family_name}. Updating."
            user.firstname = given_name if given_name.present?
            user.lastname = family_name if family_name.present?
            user.save(validate: false)
          end
        end
      end

      if user.registered? # Registered
        account_pending user
      elsif user.active? # Active
        handle_active_user user
        user.update_last_login_on!
      else # Locked
        handle_inactive_user user
      end
    end

    def logout
      if User.current.anonymous?
        redirect_to home_url
      elsif request.post?
        logout_user
        redirect_to "/oauth2/sign_out?rd=#{CGI.escape(home_url)}"
      end
    end

  end
end

unless AccountController.included_modules.include?(RedmineProxyauth::AccountControllerPatch)
  AccountController.prepend(RedmineProxyauth::AccountControllerPatch)
end
