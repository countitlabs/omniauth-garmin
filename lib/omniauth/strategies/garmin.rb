require 'omniauth'
require 'omniauth/strategies/oauth'

module OmniAuth
  module Strategies
    class Garmin < OmniAuth::Strategies::OAuth

      option :name, "garmin"
#=begin
      option :client_options, {
        scheme: :header,
        site: 'https://connectapi.garmin.com',
        request_token_path: '/oauth-service-1.0/oauth/request_token',
        access_token_path: '/oauth-service-1.0/oauth/access_token',
        authorize_url: 'https://connect.garmin.com/oauthConfirm'
      }
#=end
=begin
      option :client_options, {
        scheme: :header,
        site: 'http://connectapitest.garmin.com',
        request_token_path: '/oauth-service-1.0/oauth/request_token',
        access_token_path: '/oauth-service-1.0/oauth/access_token',
        authorize_url: 'http://connecttest.garmin.com/oauthConfirm'
      }
=end
      uid do
        access_token.token
      end

      info do
        {
          name: access_token.token
        }
      end

      def consumer
        consumer = GarminConsumer.new(options.consumer_key, options.consumer_secret, options.client_options)
        consumer.http.open_timeout = options.open_timeout if options.open_timeout
        consumer.http.read_timeout = options.read_timeout if options.read_timeout
        consumer
      end

      def callback_phase
        super
      end

      class GarminConsumer < ::OAuth::Consumer
        protected

        def create_http_request(*params)
          req = super
          if ENV['GARMIN_USERNAME']
            req.basic_auth ENV['GARMIN_USERNAME'], ENV['GARMIN_PASSWORD']
          end
          req
        end
      end
    end
  end
end
