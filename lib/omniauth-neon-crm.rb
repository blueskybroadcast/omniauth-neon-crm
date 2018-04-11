require "omniauth-neon-crm/version"
require 'omniauth/strategies/neon_crm'

module Omniauth
  module NeonCRM
    OmniAuth.config.add_camelization 'neon_crm', 'NeonCRM'
  end
end
