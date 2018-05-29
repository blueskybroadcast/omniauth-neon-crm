require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class NeonCRM < OmniAuth::Strategies::OAuth2
      API_ENDPOINT = 'https://api.neoncrm.com/neonws/services/api'.freeze

      option :name, 'neon_crm'
      option :app_options, { app_event_id: nil }
      option :client_options, {
        obtain_token_endpoint: 'https://www.z2systems.com/np/oauth/token',
        get_session_id_endpoint: API_ENDPOINT + '/common/login',
        get_user_info_endpoint: API_ENDPOINT + '/account/retrieveIndividualAccount',
        client_id: 'MUST BE PROVIDED',
        client_secret: 'MUST BE PROVIDED',
        username: 'MUST BE PROVIDED',
        password: 'MUST BE PROVIDED',
        org_id: 'MUST BE PROVIDED',
        api_key: 'MUST BE PROVIDED',
        custom_group_sync: false,
        custom_field_id: nil,
        sync_groups: false
      }

      uid { raw_info[:uid] }

      info { raw_info }

      def request_phase
        redirect session[:neon_crm_authentication_url] if session[:neon_crm_authentication_url]
      end

      def callback_phase
        @slug = request.params['slug']
        account = Account.find_by(slug: @slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        @access_token = obtain_access_token
        @user_session_id = get_user_session_id

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + @slug
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def obtain_access_token
        endpoint = options.client_options.obtain_token_endpoint
        headers = { 'Content-Type' => 'application/x-www-form-urlencoded' }
        payload = {
          client_id: options.client_options.client_id,
          client_secret: options.client_options.client_secret,
          redirect_uri: callback_url + "?slug=#{@slug}",
          code: request.params['code'],
          grant_type: 'authorization_code'
        }

        request_log_text = "NeonCRM Obtain Access Token Request:\nPOST #{endpoint}, payload: #{payload.merge(client_secret: Provider::SECURITY_MASK)}, headers: #{headers}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.post(endpoint, payload, headers)
        rescue RestClient::ExceptionWithResponse => e
          app_event_log_and_fail('Obtain Access Token', e.response, e.message)
          return nil
        end

        response_log_text = "NeonCRM User Profile Response (code: #{response.code}): \n#{response.body}"

        if response.code == 200
          @app_event.logs.create(level: 'info', text: response_log_text)
          JSON.parse(response.body)['access_token']
        else
          app_event_log_and_fail('Obtain Access Token', response)
          nil
        end
      end

      def get_user_session_id
        endpoint = options.client_options.get_session_id_endpoint
        params = {
          'login.apiKey' => options.client_options.api_key,
          'login.orgid' => options.client_options.org_id,
        }

        request_log_text = "NeonCRM Login Request:\nGET #{endpoint}, params: #{params.merge('login.apiKey' => Provider::SECURITY_MASK)}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(endpoint, params: params)
        rescue RestClient::ExceptionWithResponse => e
          app_event_log_and_fail('User Login', e.response, e.message)
          return nil
        end

        response_log_text = "NeonCRM Login Response (code: #{response.code}): \n#{response.body}"

        parsed_response = JSON.parse(response.body)
        if response.code == 200 && parsed_response.dig('loginResponse', 'operationResult').casecmp('success').zero?
          @app_event.logs.create(level: 'info', text: response_log_text)
          parsed_response['loginResponse']['userSessionId']
        else
          app_event_log_and_fail('User Login', response)
          nil
        end
      end

      def get_user_info
        endpoint = options.client_options.get_user_info_endpoint
        params = { userSessionId: @user_session_id, accountId: @access_token }

        request_log_text = "NeonCRM User Profile Request:\nGET #{endpoint}, params: #{params.merge(userSessionId: Provider::SECURITY_MASK)}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(endpoint, params: params)
        rescue RestClient::ExceptionWithResponse => e
          app_event_log_and_fail('User Profile', e.response, e.message)
          return {}
        end

        response_log_text = "NeonCRM User Profile Response (code: #{response.code}): \n#{response.body}"

        parsed_response = JSON.parse(response.body)
        user_info = parsed_response.dig('retrieveIndividualAccountResponse', 'individualAccount')

        if response.code == 200 && user_info
          @app_event.logs.create(level: 'info', text: response_log_text)

          info = {
            session_id: @user_session_id,
            uid: @access_token,
            contact_id: user_info.dig('primaryContact', 'contactId'),
            first_name: user_info.dig('primaryContact', 'firstName'),
            last_name: user_info.dig('primaryContact', 'lastName'),
            email: user_info.dig('primaryContact', 'email1'),
            username: @access_token
          }

          custom_field_codes_sync = options.client_options.custom_group_sync && options.client_options.custom_field_id.present?
          info[:individual_type_codes] = extract_individual_type_codes(user_info) if options.client_options.sync_groups
          info[:custom_field_codes] = extract_custom_field_codes(user_info) if custom_field_codes_sync

          @app_event.update(raw_data: {
            user_info: {
              uid: info[:uid],
              contact_id: info[:contact_id],
              email: info[:email],
              username: info[:username],
              first_name: info[:first_name],
              last_name: info[:last_name]
            }
          })

          info
        else
          app_event_log_and_fail('User Profile', response)
          {}
        end
      end

      private

      def extract_individual_type_codes(user_info)
        individual_types = user_info.dig('individualTypes', 'individualType')
        individual_types.map do |individual_type|
          if individual_type.is_a?(Array)
            individual_type.map { |ind_type| ind_type['name'] }
          elsif individual_type.is_a?(Hash)
            individual_type['name']
          end
        end.flatten.compact
      end

      def extract_custom_field_codes(user_info)
        custom_field_values = user_info.dig('customFieldDataList', 'customFieldData')
        if custom_field_values.is_a?(Array)
          custom_field_values.map { |custom_field_value| extract_custom_field_code(custom_field_value) }
        elsif custom_field_values.is_a?(Hash)
          [extract_custom_field_code(custom_field_values)]
        end.flatten.compact
      end

      def extract_custom_field_code(custom_field_value)
        if custom_field_value['fieldId'].to_s.casecmp(options.client_options.custom_field_id).zero?
          custom_field_value['fieldOptionId']
        end
      end

      def app_event_log_and_fail(operation, response, error_msg = '')
        error_log_text = "NeonCRM #{operation} Response Error #{error_msg} (code: #{response&.code}):\n#{response}"
        @app_event.logs.create(level: 'error', text: error_log_text)
        @app_event.fail!
      end
    end
  end
end
