# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/drivertools/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Drivertools

###
#
# This Meterpreter extensions provides functionality
# related to driver installation, removal, etc on
# Windows based targets
#
###
class Drivertools < Extension


  def initialize(client)
    super(client, 'drivertools')

    client.register_extension_aliases(
      [
        {
          'name' => 'drivertools',
          'ext'  => self
        },
      ])
  end



  def drivertools_do_work()
    request = Packet.create_request('drivertools_do_work')
    response = client.send_request(request)
    return true
  end

  def drivertools_tdl_do_nothing()
    request = Packet.create_request('drivertools_tdl_do_nothing')
    response = client.send_request(request)

    # data = Array.new

    # (response.get_tlv_values(TLV_TYPE_TDL_PCLIENT)).each do |x|
    #   data << x
    # end

    return response
  end

  # def drivertools_image_get_dev_screen
  #   request  = Packet.create_request( 'drivertools_do_work' )
  #   response = client.send_request( request )
  #   if( response.result == 0 )
  #     return response.get_tlv_value( TLV_TYPE_DEV_SCREEN )
  #   end
  #   return nil
  # end

end

end; end; end; end; end
